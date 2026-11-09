//! Resources: FindResourceA/W, FindResourceExA/W, LoadResource, LockResource, SizeofResource and
//! FreeResource, as Windows 2000's kernel32 serves them, over ntdll's LdrFindResource_U and
//! LdrAccessResource.
//!
//! A lookup is a path of three elements: the type, the name and the language. FindResource asks
//! for language 0, which ntdll searches as the FormatMessage documentation describes (the neutral
//! language, the thread's, the defaults, US English, then any); FindResourceEx for the language
//! given, which ntdll searches before the neutral one. A module handle is its image's base, the
//! program's own for NULL.
//!
//! A type or a name is a number (MAKEINTRESOURCE: the pointer's high word zero), or a string: `#`
//! and decimal digits stand for that number, as the FindResource documentation says, read by
//! ntdll's RtlUnicodeStringToInteger; any other string is a name, matched without regard to case.
//! The resource compiler stores names in upper case and ntdll matches them exactly, so kernel32
//! hands ntdll the name upper-cased by its RtlUpcaseUnicodeString, in a block of its own on the
//! process heap (an A call's converted through the ANSI code page first), as Windows 2000's
//! kernel32 imports both for. A lookup not found fails with the level's error:
//! ERROR_RESOURCE_TYPE_NOT_FOUND, ERROR_RESOURCE_NAME_NOT_FOUND or ERROR_RESOURCE_LANG_NOT_FOUND
//! (ERROR_RESOURCE_DATA_NOT_FOUND for a module without resources), mapped from ntdll's statuses.
//!
//! An HRSRC is the resource's IMAGE_RESOURCE_DATA_ENTRY, by address; the HGLOBAL LoadResource
//! answers is the data's address in the mapped image (nothing is copied, nothing is freed), which
//! LockResource hands back as it is. FreeResource is obsolete on NT and answers FALSE.

use rtl::resource::STATUS_RESOURCE_DATA_NOT_FOUND;
use rtl::status::STATUS_INVALID_PARAMETER;

use crate::edge::{wide_units, InStr, InWStr};
use crate::error::{answer, Failure, ERROR_NOT_ENOUGH_MEMORY};
use crate::heap::{HeapArray, HeapString};
use crate::ntcall::{self, ResourceId, TerminatedName};

/// A caller's resource type or name, as the API takes it: a number (MAKEINTRESOURCE), or a
/// NUL-terminated string of the call's form.
pub enum Named<'a> {
    Number(u16),
    Ansi(InStr<'a>),
    Wide(InWStr<'a>),
}

/// Whether a type or name argument is a number: its high word is zero (IS_INTRESOURCE).
fn is_number(argument: usize) -> bool {
    argument >> 16 == 0
}

impl Named<'_> {
    /// An A call's argument.
    ///
    /// # Safety
    ///
    /// `at` is a number (its high word zero) or a NUL-terminated string the call may read.
    pub unsafe fn ansi(at: *const u8) -> Self {
        if is_number(at as usize) {
            Named::Number(at as usize as u16)
        } else {
            // SAFETY: the caller's string (the contract).
            Named::Ansi(unsafe { InStr::new(at) })
        }
    }

    /// A W call's argument.
    ///
    /// # Safety
    ///
    /// `at` is a number (its high word zero) or a NUL-terminated UTF-16 string the call may read.
    pub unsafe fn wide(at: *const u16) -> Self {
        if is_number(at as usize) {
            Named::Number(at as usize as u16)
        } else {
            // SAFETY: the caller's string (the contract).
            Named::Wide(unsafe { InWStr::new(at) })
        }
    }
}

/// A type or a name as kernel32 hands it to ntdll: a number, or the name upper-cased and
/// terminated in a block of kernel32's.
enum Key {
    Number(u16),
    Name(HeapArray<u16>),
}

impl Key {
    /// The path element LdrFindResource_U takes.
    fn id(&self) -> ResourceId<'_> {
        match self {
            Key::Number(number) => ResourceId::Number(*number),
            Key::Name(units) => ResourceId::Name(
                TerminatedName::new(units).expect("a key's name is terminated when made"),
            ),
        }
    }
}

/// The most units a string type or name has: a counted string's reach.
const MOST_UNITS: usize = rtl::string::MAX_USTRING / 2;

/// The key a string stands for, as Windows 2000's kernel32 reads it through ntdll: `#` and what
/// follows is the number ntdll's RtlUnicodeStringToInteger reads there in base 10 (its digits up
/// to the first that is not one, none being zero: `"#abc"` is 0); any other string is a name,
/// upper-cased by RtlUpcaseUnicodeString into a block of kernel32's, terminated. A number past a
/// word, which no resource has, or a string past a counted string's reach is
/// STATUS_INVALID_PARAMETER.
fn key_of(units: &[u16]) -> Result<Key, Failure> {
    if units.len() > MOST_UNITS {
        return Err(Failure::Status(STATUS_INVALID_PARAMETER));
    }
    if let Some((_, digits)) = units.split_first().filter(|&(&first, _)| first == HASH) {
        let number = ntcall::unicode_string_to_integer(digits, 10).map_err(Failure::Status)?;
        return u16::try_from(number)
            .map(Key::Number)
            .map_err(|_| Failure::Status(STATUS_INVALID_PARAMETER));
    }
    // One unit more than the name: the terminator, which the new block's zeros already hold
    // (ntdll writes none).
    let mut name = HeapArray::<u16>::new(units.len() + 1)?;
    ntcall::upcase_into(units, &mut name).map_err(Failure::Status)?;
    Ok(Key::Name(name))
}

/// The unit that makes a string a number: `#`.
const HASH: u16 = b'#' as u16;

/// The key a caller's type or name stands for: a number as it is; a string as [`key_of`] reads it,
/// an A call's converted through the ANSI code page first.
fn key(named: Named<'_>) -> Result<Key, Failure> {
    match named {
        Named::Number(number) => Ok(Key::Number(number)),
        Named::Wide(text) => {
            let units = wide_units(&text).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
            key_of(&units)
        }
        Named::Ansi(text) => {
            let converted = HeapString::of_ansi(Some(&text)).map_err(Failure::Status)?;
            key_of(converted.units())
        }
    }
}

/// The module a handle names: the program's own image for NULL.
fn module_or_program(module: usize) -> usize {
    if module == 0 {
        crate::base::image_base()
    } else {
        module
    }
}

/// FindResourceEx's work (FindResource's with language 0): the HRSRC of the resource of type
/// `kind`, named `name`, in `language`, in the module (the program's for NULL); the walk's status
/// for one not found.
pub fn find_resource(
    module: usize,
    kind: Named<'_>,
    name: Named<'_>,
    language: u16,
) -> Result<usize, Failure> {
    let module = module_or_program(module);
    let kind = key(kind)?;
    let name = key(name)?;
    ntcall::find_resource(module, kind.id(), name.id(), language).map_err(Failure::Status)
}

/// LoadResource's and SizeofResource's work: the data of the resource `entry` (an HRSRC) of the
/// module (the program's for NULL), its address and size. A NULL HRSRC has no data:
/// STATUS_RESOURCE_DATA_NOT_FOUND, ERROR_RESOURCE_DATA_NOT_FOUND for both calls, as Windows 2000
/// answers; any other HRSRC that is not one faults the caller in ntdll's read.
fn resource_data(module: usize, entry: usize) -> Result<(usize, u32), Failure> {
    if entry == 0 {
        return Err(Failure::Status(STATUS_RESOURCE_DATA_NOT_FOUND));
    }
    ntcall::access_resource(module_or_program(module), entry).map_err(Failure::Status)
}

/// FindResourceA (see [`find_resource`]): the name, then the type; NULL when not found.
///
/// # Safety
///
/// `name` and `kind` are each a number (its high word zero) or a NUL-terminated string; `module`
/// is NULL or a loaded module's handle.
#[unsafe(export_name = "f2k_export_FindResourceA")]
pub unsafe extern "system" fn find_resource_a(
    module: usize,
    name: *const u8,
    kind: *const u8,
) -> usize {
    // SAFETY: the caller's arguments (the contract).
    let (kind, name) = unsafe { (Named::ansi(kind), Named::ansi(name)) };
    answer(find_resource(module, kind, name, 0), 0)
}

/// FindResourceW (see [`find_resource`]): the name, then the type; NULL when not found.
///
/// # Safety
///
/// As [`find_resource_a`]'s, the strings UTF-16.
#[unsafe(export_name = "f2k_export_FindResourceW")]
pub unsafe extern "system" fn find_resource_w(
    module: usize,
    name: *const u16,
    kind: *const u16,
) -> usize {
    // SAFETY: the caller's arguments (the contract).
    let (kind, name) = unsafe { (Named::wide(kind), Named::wide(name)) };
    answer(find_resource(module, kind, name, 0), 0)
}

/// FindResourceExA (see [`find_resource`]): the type, then the name, then the language (a WORD,
/// its dword's low half); NULL when not found.
///
/// # Safety
///
/// As [`find_resource_a`]'s.
#[unsafe(export_name = "f2k_export_FindResourceExA")]
pub unsafe extern "system" fn find_resource_ex_a(
    module: usize,
    kind: *const u8,
    name: *const u8,
    language: u32,
) -> usize {
    // SAFETY: the caller's arguments (the contract).
    let (kind, name) = unsafe { (Named::ansi(kind), Named::ansi(name)) };
    answer(find_resource(module, kind, name, language as u16), 0)
}

/// FindResourceExW (see [`find_resource`]): the type, then the name, then the language; NULL when
/// not found.
///
/// # Safety
///
/// As [`find_resource_w`]'s.
#[unsafe(export_name = "f2k_export_FindResourceExW")]
pub unsafe extern "system" fn find_resource_ex_w(
    module: usize,
    kind: *const u16,
    name: *const u16,
    language: u32,
) -> usize {
    // SAFETY: the caller's arguments (the contract).
    let (kind, name) = unsafe { (Named::wide(kind), Named::wide(name)) };
    answer(find_resource(module, kind, name, language as u16), 0)
}

/// LoadResource: the resource's data, by its address in the mapped image (see [`resource_data`]);
/// NULL when it fails.
#[unsafe(export_name = "f2k_export_LoadResource")]
pub extern "system" fn load_resource(module: usize, resource: usize) -> usize {
    answer(resource_data(module, resource).map(|(at, _)| at), 0)
}

/// SizeofResource: the resource's size in bytes (see [`resource_data`]); 0 when it fails.
#[unsafe(export_name = "f2k_export_SizeofResource")]
pub extern "system" fn sizeof_resource(module: usize, resource: usize) -> u32 {
    answer(resource_data(module, resource).map(|(_, size)| size), 0)
}

/// LockResource: the data's address, which LoadResource's handle already is.
#[unsafe(export_name = "f2k_export_LockResource")]
pub extern "system" fn lock_resource(data: usize) -> usize {
    data
}

/// FreeResource: obsolete on NT, where a loaded resource is part of its mapped image: FALSE, the
/// last error untouched.
#[unsafe(export_name = "f2k_export_FreeResource")]
pub extern "system" fn free_resource(_data: usize) -> u32 {
    0
}
