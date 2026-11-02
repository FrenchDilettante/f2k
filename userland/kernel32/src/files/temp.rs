//! The temporary files' calls, as Windows 2000's kernel32 makes them, each in its W form's work:
//! GetTempPath (the directory TMP names, else TEMP's, else USERPROFILE's, else the Windows
//! directory, made full) and
//! GetTempFileName (a name in a directory, numbered by the caller or by the call, which then makes
//! the file).

use super::handle::create_file_w;
use super::names::file_attributes;
use super::*;
use crate::base::unicode_string;
use crate::edge::{OutBuf, Text};
use crate::error::answer;

/// ERROR_BUFFER_OVERFLOW: a temporary file's name past MAX_PATH.
const ERROR_BUFFER_OVERFLOW: u32 = 111;
/// ERROR_DIRECTORY: GetTempFileName's path is not an existing directory.
const ERROR_DIRECTORY: u32 = 267;
/// CreateFile's CREATE_NEW, and the attributes the file is made with.
const CREATE_NEW: u32 = 1;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

const BACKSLASH: u16 = b'\\' as u16;

/// An environment variable's value into `value`: its length, 0 for one set to the empty string;
/// none when the variable is unset or longer than MAX_PATH characters.
fn variable(name: &[u8], value: &mut [u16; MAX_PATH + 1]) -> Option<usize> {
    let mut units = [0u16; 16];
    for (unit, &byte) in units.iter_mut().zip(name) {
        *unit = u16::from(byte);
    }
    let name = unicode_string(&mut units, name.len());
    let mut string = unicode_string(&mut value[..MAX_PATH], 0);
    let status = ntcall::query_environment_variable(&name, &mut string);
    (status == 0).then_some(usize::from(string.length) / 2)
}

/// GetTempPathW's work, Windows 2000's order: the directory TMP names, else TEMP's, else
/// USERPROFILE's, else the Windows directory. A variable set to the empty string is found all the
/// same, and the search stops at it. The directory is made full (RtlGetFullPathName_U, so a
/// relative one is under the current directory) in the caller's buffer, then a trailing backslash
/// added when it has none; whether it exists is not asked. The answer, as the utility fixture's
/// capture shows it:
///
/// - the length, when the path, its backslash and the terminator fit;
/// - otherwise the size it needs, terminator included; the buffer is not left alone, as the full
///   path is built in it before the backslash is found not to fit. A buffer too small for the full
///   path itself holds its first units, terminated, after the call: the capture says only that the
///   buffer is written, and what Windows 2000 leaves there is an assumption. A buffer of 0 is
///   untouched.
/// - 1 for an empty value, nothing written and the last error untouched: no full path is made of
///   it, and the answer is the size of a lone terminator.
fn temp_path(mut buffer: OutBuf<'_, u16>) -> Result<u32, Failure> {
    let mut path = [0u16; MAX_PATH + 1];
    let found = variable(b"TMP", &mut path)
        .or_else(|| variable(b"TEMP", &mut path))
        .or_else(|| variable(b"USERPROFILE", &mut path));
    let length = match found {
        Some(length) => length,
        None => {
            let mut root = [0u16; MAX_PATH];
            let length = crate::shared::system_root(&mut root);
            path[..length].copy_from_slice(&root[..length]);
            length
        }
    };
    path[length] = 0;
    let mut full = [0u16; MAX_PATH + 1];
    let (bytes, _) = ntcall::get_full_path_name(&path[..=length], &mut full);
    if bytes == 0 {
        return Ok(1);
    }
    if bytes > 2 * MAX_PATH {
        return Err(Failure::Error(ERROR_FILENAME_EXCED_RANGE));
    }
    let length = bytes / 2;
    let slash = usize::from(full[length - 1] != BACKSLASH);
    let size = buffer.len();
    if size <= length {
        if size != 0 {
            buffer.put(&full[..size - 1]);
            buffer.put_at(size - 1, &[0]);
        }
        return Ok((length + slash + 1) as u32);
    }
    buffer.put(&full[..length]);
    buffer.put_at(length, &[0]);
    if slash == 0 {
        return Ok(length as u32);
    }
    if size <= length + 1 {
        return Ok(length as u32 + 2);
    }
    buffer.put_at(length, &[BACKSLASH, 0]);
    Ok(length as u32 + 1)
}

/// GetTempPathA: [`temp_path`] into a buffer of kernel32's, then the path converted into the
/// caller's when it fits with its terminator (the answer its length); otherwise the size it needs,
/// nothing written. So a buffer too small is untouched here, unlike GetTempPathW's (the utility
/// fixture's capture). For an empty value the W work answers 1 and writes nothing: the empty
/// string kernel32's buffer starts as is converted, and 1 answered.
///
/// # Safety
///
/// `buffer` holds `size` bytes.
#[unsafe(export_name = "f2k_export_GetTempPathA")]
pub unsafe extern "system" fn get_temp_path_a(size: u32, buffer: *mut u8) -> u32 {
    // SAFETY: the caller's buffer (the contract).
    let buffer = unsafe { OutBuf::new(buffer, size as usize) };
    let mut path = [0u16; MAX_PATH + 1];
    let answered = answer(temp_path(OutBuf::from(&mut path[..])), 0);
    if answered == 0 || answered as usize > MAX_PATH {
        return answered;
    }
    if answered >= size {
        return answered + 1;
    }
    let length = path.iter().position(|&unit| unit == 0).unwrap_or(0);
    Text::Ansi(buffer).put_terminated(&path[..length]);
    answered
}

/// GetTempPathW (see [`temp_path`]).
///
/// # Safety
///
/// `buffer` holds `size` characters.
#[unsafe(export_name = "f2k_export_GetTempPathW")]
pub unsafe extern "system" fn get_temp_path_w(size: u32, buffer: *mut u16) -> u32 {
    // SAFETY: the caller's buffer (the contract).
    let buffer = unsafe { OutBuf::new(buffer, size as usize) };
    answer(temp_path(buffer), 0)
}

/// A temporary file's name as GetTempFileName builds it: `<path>\<prefix><number>.tmp`, the
/// backslash added only where the path has none at its end, at most three characters of the
/// prefix, the number in uppercase hexadecimal without leading zeros, the extension in lowercase
/// (the utility fixture's capture: `abcABCD.tmp`).
struct TempName {
    units: [u16; MAX_PATH],
    /// Where the number goes: the path, its backslash and the prefix before it.
    stem: usize,
    length: usize,
}

impl TempName {
    /// The name's stem from the path and the prefix; ERROR_BUFFER_OVERFLOW when even the longest
    /// number would put the name and its terminator past MAX_PATH.
    fn new(path: &[u16], prefix: &[u16]) -> Result<TempName, Failure> {
        let prefix = &prefix[..prefix.len().min(3)];
        let slash = usize::from(path.last().is_some_and(|&unit| unit != BACKSLASH));
        let stem = path.len() + slash + prefix.len();
        if stem + b"FFFF.tmp".len() >= MAX_PATH {
            return Err(Failure::Error(ERROR_BUFFER_OVERFLOW));
        }
        let mut name = TempName {
            units: [0; MAX_PATH],
            stem,
            length: stem,
        };
        name.units[..path.len()].copy_from_slice(path);
        if slash != 0 {
            name.units[path.len()] = BACKSLASH;
        }
        name.units[path.len() + slash..stem].copy_from_slice(prefix);
        Ok(name)
    }

    /// The name with `number` (its low 16 bits) after the stem.
    fn numbered(&mut self, number: u32) -> &[u16] {
        let number = number & 0xFFFF;
        let digits = (1..4)
            .take_while(|&shift| number >> (4 * shift) != 0)
            .count()
            + 1;
        let mut at = self.stem;
        for place in (0..digits).rev() {
            let digit = (number >> (4 * place)) & 0xF;
            self.units[at] = u16::from(b"0123456789ABCDEF"[digit as usize]);
            at += 1;
        }
        for &byte in b".tmp" {
            self.units[at] = u16::from(byte);
            at += 1;
        }
        self.length = at;
        &self.units[..at]
    }
}

/// How many numbers a self-numbered GetTempFileName tries: each 16-bit one but zero, once.
const NUMBERS: u32 = 0xFFFF;

/// GetTempFileNameW's work. Windows 2000 builds the name in the caller's buffer, the path first:
/// the W form's buffer holds the path, terminated, before anything else is asked, and keeps it
/// when the path is not an existing directory, which is ERROR_DIRECTORY whatever `unique` is (the
/// utility fixture's capture). With `unique` nonzero, the name with its low 16 bits, nothing made,
/// those 16 bits the answer. With zero, the call numbers the name itself, from the tick count's
/// low 16 bits (zero skipped), and makes the file (CREATE_NEW, then closed; its success clears the
/// last error): a name taken (ERROR_FILE_EXISTS) moves on to the next number, any other failure
/// is the call's, the answer the number made. The W form's buffer gets each name as it is tried
/// (the file is created by it); the A form's gets the name made, converted, on success only.
fn temp_file_name(
    path: &[u16],
    prefix: &[u16],
    unique: u32,
    mut buffer: Text<'_>,
) -> Result<u32, Failure> {
    let wide = matches!(buffer, Text::Wide(_));
    let mut name = TempName::new(path, prefix)?;
    if wide {
        buffer.put_terminated(path);
    }
    let directory = Wide::of(path)
        .and_then(|path| file_attributes(&path).ok())
        .is_some_and(|attributes| attributes & FILE_ATTRIBUTE_DIRECTORY != 0);
    if !directory {
        return Err(Failure::Error(ERROR_DIRECTORY));
    }
    if unique != 0 {
        let number = unique & 0xFFFF;
        buffer.put_terminated(name.numbered(number));
        return Ok(number);
    }
    let mut number = crate::time::get_tick_count() & 0xFFFF;
    for _ in 0..NUMBERS {
        if number == 0 {
            number = 1;
        }
        let units = name.numbered(number);
        if wide {
            buffer.put_terminated(units);
        }
        let file = Wide::of(units).ok_or(Failure::Error(ERROR_BUFFER_OVERFLOW))?;
        match create_file_w(
            &file,
            GENERIC_READ,
            0,
            None,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
        ) {
            Ok(handle) => {
                let _ = ntcall::close(handle);
                if !wide {
                    buffer.put_terminated(&name.units[..name.length]);
                }
                return Ok(number);
            }
            Err(Failure::Error(ERROR_FILE_EXISTS)) => number = (number + 1) & 0xFFFF,
            Err(failure) => return Err(failure),
        }
    }
    Err(Failure::Error(ERROR_FILE_EXISTS))
}

/// GetTempFileNameA (see [`temp_file_name`]): the path and prefix converted (a NULL one is empty).
///
/// # Safety
///
/// `path` and `prefix` are NUL-terminated strings (or NULL); `buffer` holds MAX_PATH bytes.
#[unsafe(export_name = "f2k_export_GetTempFileNameA")]
pub unsafe extern "system" fn get_temp_file_name_a(
    path: *const u8,
    prefix: *const u8,
    unique: u32,
    buffer: *mut u8,
) -> u32 {
    // SAFETY: the caller's strings (null: the empty one) and buffer (the contract).
    let (path, prefix, buffer) = unsafe {
        (
            InStr::optional(path),
            InStr::optional(prefix),
            OutBuf::new(buffer, MAX_PATH),
        )
    };
    let name = both(widen(path.as_ref()), widen(prefix.as_ref())).and_then(|(path, prefix)| {
        temp_file_name(path.text(), prefix.text(), unique, Text::Ansi(buffer))
    });
    answer(name, 0)
}

/// GetTempFileNameW (see [`temp_file_name`]).
///
/// # Safety
///
/// `path` and `prefix` are NUL-terminated UTF-16 strings (or NULL); `buffer` holds MAX_PATH
/// characters.
#[unsafe(export_name = "f2k_export_GetTempFileNameW")]
pub unsafe extern "system" fn get_temp_file_name_w(
    path: *const u16,
    prefix: *const u16,
    unique: u32,
    buffer: *mut u16,
) -> u32 {
    // SAFETY: the caller's strings (null: the empty one) and buffer (the contract).
    let (path, prefix, buffer) = unsafe {
        (
            InWStr::optional(path),
            InWStr::optional(prefix),
            OutBuf::new(buffer, MAX_PATH),
        )
    };
    let copied = |string: Option<InWStr<'_>>| match string {
        Some(string) => wide(&string),
        None => Wide::of(&[]).ok_or(Failure::Error(ERROR_PATH_NOT_FOUND)),
    };
    let name = both(copied(path), copied(prefix)).and_then(|(path, prefix)| {
        temp_file_name(path.text(), prefix.text(), unique, Text::Wide(buffer))
    });
    answer(name, 0)
}
