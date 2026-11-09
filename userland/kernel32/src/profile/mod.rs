//! The profile calls: GetPrivateProfileString and its family over a private .ini file, and
//! GetProfileString and its family over win.ini. As Windows 2000's kernel32 does, kernel32 reads
//! and writes the files itself, over ntdll's file services: a call opens the file, reads it whole,
//! answers from its text or edits it ([`ini`]: the parsing and the edits) and writes it back whole,
//! then closes it.
//!
//! - **The files.** A name without a directory or a drive in it is a file of the Windows directory
//!   (the system root); any other name is the file it names. win.ini is the Windows directory's
//!   `win.ini`, as is a private call's NULL file name. A file is ANSI text (widened through the
//!   ANSI code page, one unit a byte) unless it starts with the UTF-16 byte-order mark; an edit
//!   writes it back in its own encoding, and a file a write makes is ANSI, the A and W calls alike
//!   (a character the code page lacks becomes its default character, `?`).
//! - **The deviation.** Windows 2000 maps some files' sections to the registry (IniFileMapping,
//!   under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion), win.ini's among them, and consults
//!   the mapping before the file (`load`, `open_for_edit`). F2K has no registry on disk yet, so
//!   every section is the file's.
//! - **The strings.** An A call's strings are widened through the ANSI code page and its answers
//!   narrowed back (code page 1252: one byte a unit, so both count the same); a W call's are its
//!   own.
//! - **The answers** (the Windows 2000 machine's capture of the profile fixture). A string lookup
//!   copies the value, or the default (its trailing blanks dropped; NULL the empty one) when the
//!   file, the section or the key is missing; a NULL key lists the section's keys, a NULL section
//!   the file's sections, each name NUL-terminated and the list ended by one more NUL. A value cut
//!   to the buffer returns its size less one, a list its size less two; a buffer of no units is not
//!   written. An answer read whole from the file clears the last error; a default or a cut answer
//!   leaves it as it was. GetPrivateProfileSection of a missing section is ERROR_FILE_NOT_FOUND
//!   (and 0, the empty list). A write succeeds with the last error untouched; it fails with the
//!   file's error (a missing directory: ERROR_PATH_NOT_FOUND).
//! - **Integers.** GetPrivateProfileInt reads the value as RtlUnicodeStringToInteger reads it in
//!   base 0 (blanks, a sign, `0x` for hexadecimal, the digits up to the first that is not one:
//!   `12abc` is 12, a word 0); a missing key or an empty value is the default. A value found clears
//!   the last error.

pub mod ini;

use core::ops::Deref;

use ini::Fit;

use crate::base::{set_last_error, WideUnits};
use crate::edge::{wide_units, wide_units_of, EnvironmentBlock, InStr, InWStr, Out, OutBuf, Text};
use crate::error::{answer, bool_answer, Failure, ERROR_INVALID_PARAMETER};
use crate::files::{
    self,
    close,
    quad,
    set,
    widen,
    NtPath,
    Wide,
    ERROR_FILENAME_EXCED_RANGE,
    ERROR_FILE_NOT_FOUND,
    ERROR_NOT_ENOUGH_MEMORY,
    FILE_ALLOCATION_INFORMATION,
    FILE_END_OF_FILE_INFORMATION,
    FILE_NON_DIRECTORY_FILE,
    FILE_OPEN,
    FILE_OPEN_IF,
    FILE_POSITION_INFORMATION,
    FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_STANDARD_INFORMATION,
    FILE_SYNCHRONOUS_IO_NONALERT,
    GENERIC_READ,
    GENERIC_WRITE,
    MAX_PATH,
    STATUS_END_OF_FILE,
    STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND,
    SYNCHRONIZE,
};
use crate::heap::{HeapArray, HeapString};
use crate::nt::IoStatus;
use crate::ntcall::{self, Destination, Source, Transfer};

/// The UTF-16 byte-order mark a Unicode profile starts with.
const BYTE_ORDER_MARK: [u8; 2] = [0xFF, 0xFE];

/// A new file's attributes: FILE_ATTRIBUTE_NORMAL.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

/// win.ini, in the Windows directory.
const WIN_INI: &[u16] = &[0x77, 0x69, 0x6E, 0x2E, 0x69, 0x6E, 0x69];

/// A caller's string as an export received it: an A call's or a W call's, none for NULL.
#[derive(Clone, Copy)]
enum Name<'a> {
    Ansi(Option<InStr<'a>>),
    Wide(Option<InWStr<'a>>),
}

impl<'a> Name<'a> {
    /// The A call's string at `at`.
    ///
    /// # Safety
    ///
    /// `at` is null or a NUL-terminated string (the export's contract).
    unsafe fn ansi(at: *const u8) -> Name<'a> {
        // SAFETY: the export's contract.
        Name::Ansi(unsafe { InStr::optional(at) })
    }

    /// The W call's string at `at`.
    ///
    /// # Safety
    ///
    /// `at` is null or a NUL-terminated UTF-16 string (the export's contract).
    unsafe fn wide(at: *const u16) -> Name<'a> {
        // SAFETY: the export's contract.
        Name::Wide(unsafe { InWStr::optional(at) })
    }

    /// The string's units: an A call's widened onto the process heap, a W call's read in place;
    /// none for NULL.
    fn units(self) -> Result<Option<Units<'a>>, Failure> {
        Ok(match self {
            Name::Ansi(None) | Name::Wide(None) => None,
            Name::Ansi(Some(text)) => Some(Units::Ansi(
                HeapString::of_ansi(Some(&text)).map_err(Failure::Status)?,
            )),
            Name::Wide(Some(text)) => Some(Units::Wide(
                wide_units(&text).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?,
            )),
        })
    }

    /// The profile file the name names: win.ini for NULL; a name without a directory or a drive
    /// in the Windows directory; any other the file it names (see the module's).
    fn path(self) -> Result<Wide, Failure> {
        let name = match self {
            Name::Ansi(None) | Name::Wide(None) => return in_windows_directory(WIN_INI),
            Name::Ansi(Some(text)) => widen(Some(&text))?,
            Name::Wide(Some(text)) => files::wide(&text)?,
        };
        if ini::in_windows_directory(name.text()) {
            in_windows_directory(name.text())
        } else {
            Ok(name)
        }
    }
}

/// `name` in the Windows directory: ERROR_FILENAME_EXCED_RANGE past MAX_PATH.
fn in_windows_directory(name: &[u16]) -> Result<Wide, Failure> {
    let mut root = [0u16; MAX_PATH];
    let length = crate::shared::system_root(&mut root);
    let mut path = [0u16; MAX_PATH];
    let whole = length + 1 + name.len();
    if whole > MAX_PATH {
        return Err(Failure::Error(ERROR_FILENAME_EXCED_RANGE));
    }
    path[..length].copy_from_slice(&root[..length]);
    path[length] = u16::from(b'\\');
    path[length + 1..whole].copy_from_slice(name);
    Wide::of(&path[..whole]).ok_or(Failure::Error(ERROR_FILENAME_EXCED_RANGE))
}

/// A caller's string's units, as [`Name::units`] reads them.
enum Units<'a> {
    Ansi(HeapString),
    Wide(WideUnits<'a>),
}

impl Deref for Units<'_> {
    type Target = [u16];

    fn deref(&self) -> &[u16] {
        match self {
            Units::Ansi(string) => string.units(),
            Units::Wide(units) => units,
        }
    }
}

/// A caller's list of entries (WritePrivateProfileSection's: each NUL-terminated, an empty one
/// last), as an export received it.
enum List<'a> {
    Ansi(Option<EnvironmentBlock<'a, u8>>),
    Wide(Option<EnvironmentBlock<'a, u16>>),
}

impl List<'_> {
    /// Its units through its final empty entry, an A call's widened onto the process heap; none
    /// for NULL.
    fn units(&self) -> Result<Option<HeapArray<u16>>, Failure> {
        Ok(match self {
            List::Ansi(None) | List::Wide(None) => None,
            List::Ansi(Some(block)) => {
                let bytes = block.units().bytes();
                let mut units = HeapArray::new(bytes.len())?;
                let length = ntcall::multi_byte_to_unicode(&mut units, bytes);
                units.truncate(length);
                Some(units)
            }
            List::Wide(Some(block)) => {
                let units =
                    wide_units_of(block.units()).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
                Some(HeapArray::joined(&[&units[..]])?)
            }
        })
    }
}

/// A profile's text, as its file holds it.
struct Profile {
    text: HeapArray<u16>,
    /// Whether the file is UTF-16 (it starts with the byte-order mark), not ANSI.
    unicode: bool,
}

/// A file the call opened for itself, closed when dropped.
struct File(u32);

impl Drop for File {
    fn drop(&mut self) {
        close(self.0);
    }
}

impl File {
    /// The file at `path`, opened for `access` (with SYNCHRONIZE and FILE_READ_ATTRIBUTES) sharing
    /// `share`, as `disposition` asks (a new file plain): the open's status when it fails.
    fn open(path: &Wide, access: u32, share: u32, disposition: u32) -> Result<File, u32> {
        let path = NtPath::of(path.terminated()).ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
        let created = ntcall::create_file(
            access | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
            &path.attributes(false),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        )?;
        Ok(File(created.handle))
    }

    /// The file's text, read whole from its start (its size its end of file).
    fn read(&self) -> Result<Profile, Failure> {
        let mut standard = [0u8; 24];
        files::checked(files::query(
            self.0,
            FILE_STANDARD_INFORMATION,
            &mut standard,
        ))?;
        let size = usize::try_from(quad(&standard, 8))
            .map_err(|_| Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
        let mut bytes = HeapArray::<u8>::new(size)?;
        let mut read = 0;
        while read < size {
            let mut io_status = IoStatus::default();
            let status = ntcall::read_file(
                self.0,
                Transfer::AtPosition,
                &mut Out::from(&mut io_status),
                Destination::of(&mut bytes[read..]),
            );
            if status == STATUS_END_OF_FILE {
                break;
            }
            files::checked(status)?;
            if io_status.information == 0 {
                break;
            }
            read += io_status.information as usize;
        }
        bytes.truncate(read);
        decode(&bytes)
    }

    /// The file made `bytes`: written from its start, its end of file and allocation set after
    /// them.
    fn rewrite(&self, bytes: &[u8]) -> Result<(), Failure> {
        files::checked(set(self.0, FILE_POSITION_INFORMATION, &0u64.to_le_bytes()))?;
        let mut io_status = IoStatus::default();
        files::checked(ntcall::write_file(
            self.0,
            Transfer::AtPosition,
            &mut Out::from(&mut io_status),
            Source::of(bytes),
        ))?;
        let end = (bytes.len() as u64).to_le_bytes();
        files::checked(set(self.0, FILE_END_OF_FILE_INFORMATION, &end))?;
        files::checked(set(self.0, FILE_ALLOCATION_INFORMATION, &end))
    }
}

/// A file's bytes as text: UTF-16 after a byte-order mark, ANSI otherwise.
fn decode(bytes: &[u8]) -> Result<Profile, Failure> {
    if let Some(units) = bytes.strip_prefix(&BYTE_ORDER_MARK) {
        let mut text = HeapArray::new(units.len() / 2)?;
        for (unit, pair) in text.iter_mut().zip(units.as_chunks::<2>().0) {
            *unit = u16::from_le_bytes(*pair);
        }
        return Ok(Profile {
            text,
            unicode: true,
        });
    }
    let mut text = HeapArray::new(bytes.len())?;
    let length = ntcall::multi_byte_to_unicode(&mut text, bytes);
    text.truncate(length);
    Ok(Profile {
        text,
        unicode: false,
    })
}

/// Text as a file's bytes: UTF-16 after a byte-order mark, or ANSI.
fn encode(text: &[u16], unicode: bool) -> Result<HeapArray<u8>, Failure> {
    if unicode {
        let mut bytes = HeapArray::new(BYTE_ORDER_MARK.len() + 2 * text.len())?;
        bytes[..2].copy_from_slice(&BYTE_ORDER_MARK);
        for (pair, unit) in bytes[2..].as_chunks_mut::<2>().0.iter_mut().zip(text) {
            *pair = unit.to_le_bytes();
        }
        return Ok(bytes);
    }
    let mut bytes = HeapArray::new(ntcall::unicode_to_multi_byte_size(text))?;
    ntcall::unicode_to_multi_byte_into(&mut bytes, text);
    Ok(bytes)
}

/// The profile at `path`, read for a lookup: none when it cannot be opened (a missing file is the
/// defaults'). Windows 2000 consults the file's IniFileMapping here first, and answers a mapped
/// section from the registry; F2K has no registry on disk yet and reads the file (a deviation).
fn load(path: &Wide) -> Result<Option<Profile>, Failure> {
    match File::open(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
    ) {
        Ok(file) => file.read().map(Some),
        Err(_) => Ok(None),
    }
}

/// The profile at `path` opened for an edit, for reading and writing, and read: made when missing,
/// unless the edit only `deletes` (none then: a missing file has nothing to delete). As for
/// `load`, Windows 2000 would write a section its IniFileMapping maps to the registry; F2K
/// writes the file.
fn open_for_edit(path: &Wide, deletes: bool) -> Result<Option<(File, Profile)>, Failure> {
    let disposition = if deletes { FILE_OPEN } else { FILE_OPEN_IF };
    let file = match File::open(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        disposition,
    ) {
        Ok(file) => file,
        Err(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND) if deletes => {
            return Ok(None)
        }
        Err(status) => return Err(Failure::Status(status)),
    };
    let profile = file.read()?;
    Ok(Some((file, profile)))
}

/// An edit's splice applied to the profile's text and the file written back whole, in its own
/// encoding; nothing written for no splice (nothing to delete).
fn save(file: &File, profile: &Profile, splice: Option<ini::Splice<'_>>) -> Result<(), Failure> {
    let Some(splice) = splice else {
        return Ok(());
    };
    let text = HeapArray::joined(&splice.pieces(&profile.text))?;
    file.rewrite(&encode(&text, profile.unicode)?)
}

/// An answer's units into the caller's buffer, as `fit` says: its first units, then its NULs.
fn put(out: &mut Text<'_>, answer: impl Iterator<Item = u16>, fit: Fit) -> Result<u32, Failure> {
    let mut units = HeapArray::new(fit.units + fit.terminators)?;
    for (unit, value) in units.iter_mut().zip(answer.take(fit.units)) {
        *unit = value;
    }
    if !units.is_empty() {
        out.put(&units);
    }
    Ok(fit.count)
}

/// A string answer: the string, cut to the buffer.
fn put_string(out: &mut Text<'_>, string: &[u16]) -> Result<(Fit, u32), Failure> {
    let fit = ini::fit_string(string.len(), out.len());
    Ok((fit, put(out, string.iter().copied(), fit)?))
}

/// A list answer: the list, cut to the buffer.
fn put_list(
    out: &mut Text<'_>,
    list: impl Iterator<Item = u16> + Clone,
) -> Result<(Fit, u32), Failure> {
    let fit = ini::fit_list(list.clone().count(), out.len());
    Ok((fit, put(out, list, fit)?))
}

/// An answer read whole from the file clears the last error; a cut one leaves it.
fn read_from_file(fit: Fit, count: u32) -> u32 {
    if fit.whole {
        set_last_error(0);
    }
    count
}

/// GetPrivateProfileString's work (see the module's): the units of the answer, its NUL left out.
fn profile_string(
    section: Name<'_>,
    key: Name<'_>,
    default: Name<'_>,
    mut out: Text<'_>,
    file: Name<'_>,
) -> Result<u32, Failure> {
    let section = section.units()?;
    let key = key.units()?;
    let default = default.units()?;
    let path = file.path()?;
    if out.is_empty() {
        return Ok(0);
    }
    if let Some(profile) = load(&path)? {
        let text = &profile.text[..];
        match (&section, &key) {
            (None, _) => {
                let (fit, count) = put_list(&mut out, ini::section_names(text))?;
                return Ok(read_from_file(fit, count));
            }
            (Some(section), None) => {
                if let Some(found) = ini::section(text, section) {
                    let (fit, count) = put_list(&mut out, ini::key_names(text, &found))?;
                    return Ok(read_from_file(fit, count));
                }
            }
            (Some(section), Some(key)) => {
                if let Some(value) = ini::value(text, section, key) {
                    let (fit, count) = put_string(&mut out, value)?;
                    return Ok(read_from_file(fit, count));
                }
            }
        }
    }
    let default = default.as_deref().unwrap_or(&[]);
    put_string(&mut out, ini::without_trailing_blanks(default)).map(|(_, count)| count)
}

/// GetPrivateProfileInt's work (see the module's): the value read as an integer, or the default.
fn profile_int(section: Name<'_>, key: Name<'_>, default: u32, file: Name<'_>) -> u32 {
    let looked_up = || -> Result<u32, Failure> {
        let (Some(section), Some(key)) = (section.units()?, key.units()?) else {
            return Ok(default);
        };
        let Some(profile) = load(&file.path()?)? else {
            return Ok(default);
        };
        let Some(value) = ini::value(&profile.text, &section, &key) else {
            return Ok(default);
        };
        set_last_error(0);
        if value.is_empty() {
            return Ok(default);
        }
        Ok(ntcall::unicode_string_to_integer(value, 0).unwrap_or(default))
    };
    looked_up().unwrap_or(default)
}

/// GetPrivateProfileSection's work (see the module's).
fn profile_section(section: Name<'_>, mut out: Text<'_>, file: Name<'_>) -> Result<u32, Failure> {
    let section = section.units()?;
    let path = file.path()?;
    if let (Some(profile), Some(section)) = (load(&path)?, &section) {
        let text = &profile.text[..];
        if let Some(found) = ini::section(text, section) {
            let (fit, count) = put_list(&mut out, ini::section_entries(text, &found))?;
            return Ok(read_from_file(fit, count));
        }
    }
    put_list(&mut out, core::iter::once(0))?;
    Err(Failure::Error(ERROR_FILE_NOT_FOUND))
}

/// GetPrivateProfileSectionNames's work (see the module's): a missing file's list is empty.
fn profile_section_names(mut out: Text<'_>, file: Name<'_>) -> Result<u32, Failure> {
    let path = file.path()?;
    match load(&path)? {
        Some(profile) => {
            let (fit, count) = put_list(&mut out, ini::section_names(&profile.text))?;
            Ok(read_from_file(fit, count))
        }
        None => put_list(&mut out, core::iter::once(0)).map(|(_, count)| count),
    }
}

/// WritePrivateProfileString's work (see the module's): a NULL key deletes the section, a NULL
/// value the key. A NULL section with nothing else asks a flush of what the system caches of the
/// file, and has nothing to flush here; with a key or a value it is ERROR_INVALID_PARAMETER.
fn write_profile_string(
    section: Name<'_>,
    key: Name<'_>,
    value: Name<'_>,
    file: Name<'_>,
) -> Result<(), Failure> {
    let section = section.units()?;
    let key = key.units()?;
    let value = value.units()?;
    let path = file.path()?;
    let Some(section) = section else {
        if key.is_none() && value.is_none() {
            return Ok(());
        }
        return Err(Failure::Error(ERROR_INVALID_PARAMETER));
    };
    let deletes = key.is_none() || value.is_none();
    let Some((file, profile)) = open_for_edit(&path, deletes)? else {
        return Ok(());
    };
    let text = &profile.text[..];
    let splice = match (&key, &value) {
        (None, _) => ini::delete_section(text, &section),
        (Some(key), None) => ini::delete_key(text, &section, key),
        (Some(key), Some(value)) => Some(ini::write_key(text, &section, key, value)),
    };
    save(&file, &profile, splice)
}

/// WritePrivateProfileSection's work (see the module's): the section's entries replaced by the
/// list's, each line as the caller wrote it; a NULL list deletes the section.
fn write_profile_section(section: Name<'_>, list: List<'_>, file: Name<'_>) -> Result<(), Failure> {
    let section = section.units()?;
    let list = list.units()?;
    let path = file.path()?;
    let Some(section) = section else {
        return Err(Failure::Error(ERROR_INVALID_PARAMETER));
    };
    let body = match &list {
        Some(list) => {
            let lines = ini::section_body(list);
            let mut body = HeapArray::new(lines.clone().count())?;
            for (unit, value) in body.iter_mut().zip(lines) {
                *unit = value;
            }
            Some(body)
        }
        None => None,
    };
    let Some((file, profile)) = open_for_edit(&path, body.is_none())? else {
        return Ok(());
    };
    let text = &profile.text[..];
    let splice = match &body {
        Some(body) => Some(ini::write_section(text, &section, body)),
        None => ini::delete_section(text, &section),
    };
    save(&file, &profile, splice)
}

/// GetPrivateProfileStringA (see [`profile_string`]).
///
/// # Safety
///
/// The strings are null or NUL-terminated; `buffer` holds `size` bytes.
#[unsafe(export_name = "f2k_export_GetPrivateProfileStringA")]
pub unsafe extern "system" fn get_private_profile_string_a(
    section: *const u8,
    key: *const u8,
    default: *const u8,
    buffer: *mut u8,
    size: u32,
    file: *const u8,
) -> u32 {
    // SAFETY: the caller's strings and buffer (the contract).
    let (section, key, default, buffer, file) = unsafe {
        (
            Name::ansi(section),
            Name::ansi(key),
            Name::ansi(default),
            OutBuf::new(buffer, size as usize),
            Name::ansi(file),
        )
    };
    answer(
        profile_string(section, key, default, Text::Ansi(buffer), file),
        0,
    )
}

/// GetPrivateProfileStringW (see [`profile_string`]).
///
/// # Safety
///
/// The strings are null or NUL-terminated; `buffer` holds `size` characters.
#[unsafe(export_name = "f2k_export_GetPrivateProfileStringW")]
pub unsafe extern "system" fn get_private_profile_string_w(
    section: *const u16,
    key: *const u16,
    default: *const u16,
    buffer: *mut u16,
    size: u32,
    file: *const u16,
) -> u32 {
    // SAFETY: the caller's strings and buffer (the contract).
    let (section, key, default, buffer, file) = unsafe {
        (
            Name::wide(section),
            Name::wide(key),
            Name::wide(default),
            OutBuf::new(buffer, size as usize),
            Name::wide(file),
        )
    };
    answer(
        profile_string(section, key, default, Text::Wide(buffer), file),
        0,
    )
}

/// GetProfileStringA: GetPrivateProfileStringA's over win.ini. Windows 2000 would consult win.ini's
/// IniFileMapping first, the sections it maps to the registry; F2K reads the file only (see the
/// module's).
///
/// # Safety
///
/// As [`get_private_profile_string_a`]'s.
#[unsafe(export_name = "f2k_export_GetProfileStringA")]
pub unsafe extern "system" fn get_profile_string_a(
    section: *const u8,
    key: *const u8,
    default: *const u8,
    buffer: *mut u8,
    size: u32,
) -> u32 {
    // SAFETY: the caller's contract, the file name none: win.ini.
    unsafe { get_private_profile_string_a(section, key, default, buffer, size, core::ptr::null()) }
}

/// GetProfileStringW (as [`get_profile_string_a`]).
///
/// # Safety
///
/// As [`get_private_profile_string_w`]'s.
#[unsafe(export_name = "f2k_export_GetProfileStringW")]
pub unsafe extern "system" fn get_profile_string_w(
    section: *const u16,
    key: *const u16,
    default: *const u16,
    buffer: *mut u16,
    size: u32,
) -> u32 {
    // SAFETY: the caller's contract, the file name none: win.ini.
    unsafe { get_private_profile_string_w(section, key, default, buffer, size, core::ptr::null()) }
}

/// GetPrivateProfileIntA (see [`profile_int`]).
///
/// # Safety
///
/// The strings are null or NUL-terminated.
#[unsafe(export_name = "f2k_export_GetPrivateProfileIntA")]
pub unsafe extern "system" fn get_private_profile_int_a(
    section: *const u8,
    key: *const u8,
    default: u32,
    file: *const u8,
) -> u32 {
    // SAFETY: the caller's strings (the contract).
    let (section, key, file) = unsafe { (Name::ansi(section), Name::ansi(key), Name::ansi(file)) };
    profile_int(section, key, default, file)
}

/// GetPrivateProfileIntW (see [`profile_int`]).
///
/// # Safety
///
/// The strings are null or NUL-terminated.
#[unsafe(export_name = "f2k_export_GetPrivateProfileIntW")]
pub unsafe extern "system" fn get_private_profile_int_w(
    section: *const u16,
    key: *const u16,
    default: u32,
    file: *const u16,
) -> u32 {
    // SAFETY: the caller's strings (the contract).
    let (section, key, file) = unsafe { (Name::wide(section), Name::wide(key), Name::wide(file)) };
    profile_int(section, key, default, file)
}

/// GetProfileIntA: GetPrivateProfileIntA's over win.ini, its IniFileMapping not consulted (as
/// [`get_profile_string_a`]).
///
/// # Safety
///
/// The strings are null or NUL-terminated.
#[unsafe(export_name = "f2k_export_GetProfileIntA")]
pub unsafe extern "system" fn get_profile_int_a(
    section: *const u8,
    key: *const u8,
    default: u32,
) -> u32 {
    // SAFETY: the caller's contract, the file name none: win.ini.
    unsafe { get_private_profile_int_a(section, key, default, core::ptr::null()) }
}

/// GetProfileIntW (as [`get_profile_int_a`]).
///
/// # Safety
///
/// The strings are null or NUL-terminated.
#[unsafe(export_name = "f2k_export_GetProfileIntW")]
pub unsafe extern "system" fn get_profile_int_w(
    section: *const u16,
    key: *const u16,
    default: u32,
) -> u32 {
    // SAFETY: the caller's contract, the file name none: win.ini.
    unsafe { get_private_profile_int_w(section, key, default, core::ptr::null()) }
}

/// GetPrivateProfileSectionA (see [`profile_section`]).
///
/// # Safety
///
/// The strings are null or NUL-terminated; `buffer` holds `size` bytes.
#[unsafe(export_name = "f2k_export_GetPrivateProfileSectionA")]
pub unsafe extern "system" fn get_private_profile_section_a(
    section: *const u8,
    buffer: *mut u8,
    size: u32,
    file: *const u8,
) -> u32 {
    // SAFETY: the caller's strings and buffer (the contract).
    let (section, buffer, file) = unsafe {
        (
            Name::ansi(section),
            OutBuf::new(buffer, size as usize),
            Name::ansi(file),
        )
    };
    answer(profile_section(section, Text::Ansi(buffer), file), 0)
}

/// GetPrivateProfileSectionW (see [`profile_section`]).
///
/// # Safety
///
/// The strings are null or NUL-terminated; `buffer` holds `size` characters.
#[unsafe(export_name = "f2k_export_GetPrivateProfileSectionW")]
pub unsafe extern "system" fn get_private_profile_section_w(
    section: *const u16,
    buffer: *mut u16,
    size: u32,
    file: *const u16,
) -> u32 {
    // SAFETY: the caller's strings and buffer (the contract).
    let (section, buffer, file) = unsafe {
        (
            Name::wide(section),
            OutBuf::new(buffer, size as usize),
            Name::wide(file),
        )
    };
    answer(profile_section(section, Text::Wide(buffer), file), 0)
}

/// GetPrivateProfileSectionNamesA (see [`profile_section_names`]).
///
/// # Safety
///
/// `buffer` holds `size` bytes; `file` is null or NUL-terminated.
#[unsafe(export_name = "f2k_export_GetPrivateProfileSectionNamesA")]
pub unsafe extern "system" fn get_private_profile_section_names_a(
    buffer: *mut u8,
    size: u32,
    file: *const u8,
) -> u32 {
    // SAFETY: the caller's buffer and string (the contract).
    let (buffer, file) = unsafe { (OutBuf::new(buffer, size as usize), Name::ansi(file)) };
    answer(profile_section_names(Text::Ansi(buffer), file), 0)
}

/// GetPrivateProfileSectionNamesW (see [`profile_section_names`]).
///
/// # Safety
///
/// `buffer` holds `size` characters; `file` is null or NUL-terminated.
#[unsafe(export_name = "f2k_export_GetPrivateProfileSectionNamesW")]
pub unsafe extern "system" fn get_private_profile_section_names_w(
    buffer: *mut u16,
    size: u32,
    file: *const u16,
) -> u32 {
    // SAFETY: the caller's buffer and string (the contract).
    let (buffer, file) = unsafe { (OutBuf::new(buffer, size as usize), Name::wide(file)) };
    answer(profile_section_names(Text::Wide(buffer), file), 0)
}

/// WritePrivateProfileStringA (see [`write_profile_string`]).
///
/// # Safety
///
/// The strings are null or NUL-terminated.
#[unsafe(export_name = "f2k_export_WritePrivateProfileStringA")]
pub unsafe extern "system" fn write_private_profile_string_a(
    section: *const u8,
    key: *const u8,
    value: *const u8,
    file: *const u8,
) -> u32 {
    // SAFETY: the caller's strings (the contract).
    let names = unsafe {
        (
            Name::ansi(section),
            Name::ansi(key),
            Name::ansi(value),
            Name::ansi(file),
        )
    };
    bool_answer(write_profile_string(names.0, names.1, names.2, names.3))
}

/// WritePrivateProfileStringW (see [`write_profile_string`]).
///
/// # Safety
///
/// The strings are null or NUL-terminated.
#[unsafe(export_name = "f2k_export_WritePrivateProfileStringW")]
pub unsafe extern "system" fn write_private_profile_string_w(
    section: *const u16,
    key: *const u16,
    value: *const u16,
    file: *const u16,
) -> u32 {
    // SAFETY: the caller's strings (the contract).
    let names = unsafe {
        (
            Name::wide(section),
            Name::wide(key),
            Name::wide(value),
            Name::wide(file),
        )
    };
    bool_answer(write_profile_string(names.0, names.1, names.2, names.3))
}

/// WriteProfileStringA: WritePrivateProfileStringA's on win.ini, its IniFileMapping not consulted
/// (as [`get_profile_string_a`]).
///
/// # Safety
///
/// The strings are null or NUL-terminated.
#[unsafe(export_name = "f2k_export_WriteProfileStringA")]
pub unsafe extern "system" fn write_profile_string_a(
    section: *const u8,
    key: *const u8,
    value: *const u8,
) -> u32 {
    // SAFETY: the caller's contract, the file name none: win.ini.
    unsafe { write_private_profile_string_a(section, key, value, core::ptr::null()) }
}

/// WriteProfileStringW (as [`write_profile_string_a`]).
///
/// # Safety
///
/// The strings are null or NUL-terminated.
#[unsafe(export_name = "f2k_export_WriteProfileStringW")]
pub unsafe extern "system" fn write_profile_string_w(
    section: *const u16,
    key: *const u16,
    value: *const u16,
) -> u32 {
    // SAFETY: the caller's contract, the file name none: win.ini.
    unsafe { write_private_profile_string_w(section, key, value, core::ptr::null()) }
}

/// WritePrivateProfileSectionA (see [`write_profile_section`]).
///
/// # Safety
///
/// `section` and `file` are null or NUL-terminated; `list` null or a list of NUL-terminated
/// entries, an empty one last.
#[unsafe(export_name = "f2k_export_WritePrivateProfileSectionA")]
pub unsafe extern "system" fn write_private_profile_section_a(
    section: *const u8,
    list: *const u8,
    file: *const u8,
) -> u32 {
    // SAFETY: the caller's strings and list (the contract).
    let (section, list, file) = unsafe {
        (
            Name::ansi(section),
            List::Ansi((!list.is_null()).then(|| EnvironmentBlock::new(list))),
            Name::ansi(file),
        )
    };
    bool_answer(write_profile_section(section, list, file))
}

/// WritePrivateProfileSectionW (see [`write_profile_section`]).
///
/// # Safety
///
/// As [`write_private_profile_section_a`]'s, of UTF-16 units.
#[unsafe(export_name = "f2k_export_WritePrivateProfileSectionW")]
pub unsafe extern "system" fn write_private_profile_section_w(
    section: *const u16,
    list: *const u16,
    file: *const u16,
) -> u32 {
    // SAFETY: the caller's strings and list (the contract).
    let (section, list, file) = unsafe {
        (
            Name::wide(section),
            List::Wide((!list.is_null()).then(|| EnvironmentBlock::new(list))),
            Name::wide(file),
        )
    };
    bool_answer(write_profile_section(section, list, file))
}
