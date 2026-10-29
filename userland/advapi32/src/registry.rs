//! The registry calls: RegCreateKeyEx, RegOpenKeyEx and RegOpenKey, RegCloseKey, RegDeleteKey,
//! RegEnumKey, RegSetValueEx and RegQueryValueEx, RegSetValue and RegQueryValue, W and A, as
//! Windows 2000's advapi32 runs them: user-mode code over ntdll's key services (NtCreateKey,
//! NtOpenKey...), a failed service's NTSTATUS mapped to the Win32 error the call returns through
//! RtlNtStatusToDosError. The calls return their error and leave the last error alone.
//!
//! The predefined keys (HKEY_CLASSES_ROOT 0x80000000 to HKEY_DYN_DATA 0x80000006) stand for
//! their NT keys: HKEY_LOCAL_MACHINE `\Registry\Machine`, HKEY_USERS `\Registry\User`,
//! HKEY_CURRENT_USER the current user's hive (RtlOpenCurrentUser), HKEY_CLASSES_ROOT
//! `\Registry\Machine\Software\Classes`, HKEY_CURRENT_CONFIG the current hardware profile; each
//! is opened at its first use in the process and kept, and RegCloseKey of one closes what it
//! kept (the next use opens it again). HKEY_PERFORMANCE_DATA and HKEY_DYN_DATA (Windows 95's)
//! have no key: ERROR_INVALID_HANDLE.
//!
//! The A calls convert their names to Unicode and call the W core; their string values
//! (REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ) are kept in Unicode, converted on the way in, and on the
//! way out converted in the caller's buffer, where the Unicode data is read first: the sizes they
//! report are the ANSI ones. A string value set without its terminator gets one (as the capture
//! of Windows 2000 reads it back).
//!
//! The exports take the caller's strings, buffers and out parameters as slices and [`Out`]s; a
//! buffer at a null address with a length is one the call cannot reach: ERROR_NOACCESS, as a
//! service answers an address it cannot write.

use core::sync::atomic::{AtomicU32, Ordering};

use rtl::cstr;
use rtl::status::{
    NtStatus,
    STATUS_BUFFER_OVERFLOW,
    STATUS_INVALID_HANDLE,
    STATUS_NO_MEMORY,
    STATUS_OBJECT_NAME_NOT_FOUND,
};

use crate::imports::{self as nt, Counted, HeapBlock, KeyAttributes, Wide};
use crate::{caller_bytes, caller_bytes_mut, Out};

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const ERROR_INVALID_DATA: u32 = 13;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_MORE_DATA: u32 = 234;
pub const ERROR_NOACCESS: u32 = 998;

/// OBJECT_ATTRIBUTES' attributes: the handle inherited, the name compared case-insensitively.
const OBJ_INHERIT: u32 = 0x02;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;

/// The key rights the calls ask for.
const KEY_QUERY_VALUE: u32 = 0x0001;
const KEY_SET_VALUE: u32 = 0x0002;
const DELETE: u32 = 0x0001_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// The value types whose data is text.
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_MULTI_SZ: u32 = 7;

/// The information classes the calls read: KEY_BASIC_INFORMATION (its name at offset 16) and
/// KEY_VALUE_PARTIAL_INFORMATION (its type at 4, its data's length at 8, the data at 12).
const KEY_BASIC_INFORMATION: u32 = 0;
const KEY_VALUE_PARTIAL_INFORMATION: u32 = 2;
const BASIC_NAME: usize = 16;
const PARTIAL_DATA: usize = 12;

/// The predefined keys: their first handle value and how many there are.
const PREDEFINED_FIRST: u32 = 0x8000_0000;
const PREDEFINED_COUNT: usize = 7;

/// The longest key name, in units (a subkey's name, as RegEnumKey reads it).
const MAX_KEY_NAME: usize = 255;

/// The predefined keys' NT handles, once opened (zero before).
static PREDEFINED: [AtomicU32; PREDEFINED_COUNT] = [const { AtomicU32::new(0) }; PREDEFINED_COUNT];

/// A SECURITY_ATTRIBUTES, as RegCreateKeyEx reads it: its length, its security descriptor and
/// whether the handle is inherited.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecurityAttributes {
    pub length: u32,
    pub security_descriptor: usize,
    pub inherit_handle: u32,
}

/// Whether a value's data is text.
pub fn is_text(kind: u32) -> bool {
    matches!(kind, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ)
}

/// The predefined key `key` is, by its place (HKEY_CLASSES_ROOT first).
pub fn predefined(key: u32) -> Option<usize> {
    let index = key.wrapping_sub(PREDEFINED_FIRST) as usize;
    (index < PREDEFINED_COUNT).then_some(index)
}

/// The Win32 error a failed service's status maps to.
fn error(status: NtStatus) -> u32 {
    nt::dos_error(status)
}

/// A service's answer as a call's error: ERROR_SUCCESS, or its status's.
fn code(answer: Result<(), NtStatus>) -> u32 {
    answer.map_or_else(error, |()| ERROR_SUCCESS)
}

/// Write `value` to the out parameter, when the caller gave one.
fn give(out: Option<&mut Out<'_, u32>>, value: u32) {
    if let Some(out) = out {
        out.set(value);
    }
}

/// The caller's NUL-terminated string at `text`, its terminator left out (the empty string for
/// null).
///
/// # Safety
///
/// `text` is null, or an aligned NUL-terminated string the call may read for `'a`.
unsafe fn wide_text<'a>(text: *const u16) -> &'a [u16] {
    if text.is_null() {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { cstr::units_until_nul(text) }
}

/// The caller's NUL-terminated ANSI string at `text`, its terminator left out (the empty string
/// for null).
///
/// # Safety
///
/// `text` is null, or a NUL-terminated string the call may read for `'a`.
unsafe fn ansi_text<'a>(text: *const u8) -> &'a [u8] {
    if text.is_null() {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { cstr::bytes_until_nul(text) }
}

/// The bytes of the caller's NUL-terminated string at `text`, its terminator's included: none for
/// null (a string the call cannot reach).
///
/// # Safety
///
/// `text` is null, or an aligned NUL-terminated string the call may read for `'a`.
unsafe fn wide_text_bytes<'a>(text: *const u16) -> Option<&'a [u8]> {
    if text.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let units = unsafe { cstr::units_until_nul(text) };
    // SAFETY: the units read above and their terminator.
    unsafe { caller_bytes(text.cast(), 2 * units.len() + 2) }
}

/// The NT path of a predefined key opened by its name.
fn predefined_path(index: usize) -> Option<&'static [u8]> {
    match index {
        0 => Some(b"\\Registry\\Machine\\Software\\Classes"),
        2 => Some(b"\\Registry\\Machine"),
        3 => Some(b"\\Registry\\User"),
        5 => Some(b"\\Registry\\Machine\\System\\CurrentControlSet\\Hardware Profiles\\Current"),
        _ => None,
    }
}

/// Open predefined key `index`: its NT handle, or the status.
fn open_predefined(index: usize) -> Result<u32, NtStatus> {
    if index == 1 {
        return nt::open_current_user(MAXIMUM_ALLOWED);
    }
    let path = predefined_path(index).ok_or(NtStatus(STATUS_INVALID_HANDLE))?;
    let mut units = [0u16; 80];
    for (unit, &byte) in units.iter_mut().zip(path) {
        *unit = byte as u16;
    }
    let name = Counted::new(&units[..path.len()]);
    nt::open_key(&attributes(0, &name, false), MAXIMUM_ALLOWED)
}

/// The NT handle `key` stands for: itself, or a predefined key's, opened at its first use. A
/// predefined key that cannot be opened is the open's error.
fn map(key: u32) -> Result<u32, u32> {
    let Some(index) = predefined(key) else {
        return Ok(key);
    };
    let kept = PREDEFINED[index].load(Ordering::Acquire);
    if kept != 0 {
        return Ok(kept);
    }
    let opened = open_predefined(index).map_err(error)?;
    match PREDEFINED[index].compare_exchange(0, opened, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(opened),
        Err(other) => {
            // Another thread opened it first: its handle is the one kept.
            let _ = nt::close(opened);
            Ok(other)
        }
    }
}

/// The ANSI string `text` converted to Unicode: ERROR_NOT_ENOUGH_MEMORY when the heap has no
/// room for it.
fn wide(text: &[u8]) -> Result<Wide, u32> {
    nt::ansi_to_unicode(text).map_err(|status| {
        if status == NtStatus(STATUS_NO_MEMORY) {
            ERROR_NOT_ENOUGH_MEMORY
        } else {
            error(status)
        }
    })
}

/// A zeroed block of `size` bytes of the process heap: ERROR_NOT_ENOUGH_MEMORY when it has no
/// room.
fn block(size: usize) -> Result<HeapBlock, u32> {
    HeapBlock::new(size).ok_or(ERROR_NOT_ENOUGH_MEMORY)
}

/// The OBJECT_ATTRIBUTES naming `name` below `root` (zero: an absolute name).
fn attributes<'a>(root: u32, name: &'a Counted, inherit: bool) -> KeyAttributes<'a> {
    KeyAttributes::new(
        root,
        name,
        OBJ_CASE_INSENSITIVE | if inherit { OBJ_INHERIT } else { 0 },
    )
}

/// A handle the calls opened for themselves, closed when dropped.
struct Opened(u32);

impl Drop for Opened {
    fn drop(&mut self) {
        let _ = nt::close(self.0);
    }
}

// --- The W core ----------------------------------------------------------------------------------

/// Create `path` below the NT key `root` key by key, each missing one made, the last with
/// `class` and `access`: what RegCreateKeyEx does once the whole path's create found a key on the
/// way missing. The last key's handle and disposition, or the status.
fn create_levels(
    root: u32,
    path: &Counted,
    class: Option<&Counted>,
    options: u32,
    access: u32,
    inherit: bool,
) -> Result<(u32, u32), NtStatus> {
    let units = path.units();
    let units = units.strip_suffix(&[b'\\' as u16]).unwrap_or(units);
    let mut parent: Option<Opened> = None;
    let mut names = units.split(|&unit| unit == b'\\' as u16).peekable();
    while let Some(name) = names.next() {
        let last = names.peek().is_none();
        let name = Counted::new(name);
        let at = parent.as_ref().map_or(root, |parent| parent.0);
        let (handle, disposition) = nt::create_key(
            &attributes(at, &name, last && inherit),
            if last { access } else { MAXIMUM_ALLOWED },
            if last { class } else { None },
            options,
        )?;
        if last {
            return Ok((handle, disposition));
        }
        parent = Some(Opened(handle));
    }
    Err(NtStatus(STATUS_OBJECT_NAME_NOT_FOUND))
}

/// RegCreateKeyExW's core: `path` below `key`, made with every missing key above it.
#[allow(clippy::too_many_arguments)]
fn create_key(
    key: u32,
    path: &Counted,
    class: Option<&Counted>,
    options: u32,
    access: u32,
    inherit: bool,
    result: Option<&mut Out<'_, u32>>,
    disposition: Option<&mut Out<'_, u32>>,
) -> u32 {
    if key == 0 {
        return ERROR_INVALID_HANDLE;
    }
    let root = match map(key) {
        Ok(root) => root,
        Err(code) => {
            give(result, 0);
            return code;
        }
    };
    let created = match nt::create_key(&attributes(root, path, inherit), access, class, options) {
        Err(NtStatus(STATUS_OBJECT_NAME_NOT_FOUND)) => {
            create_levels(root, path, class, options, access, inherit)
        }
        created => created,
    };
    match created {
        Ok((handle, outcome)) => {
            give(result, handle);
            give(disposition, outcome);
            ERROR_SUCCESS
        }
        Err(status) => {
            give(result, 0);
            error(status)
        }
    }
}

/// RegOpenKeyExW's core: `path` below `key` opened with `access`.
fn open_key(key: u32, path: &Counted, access: u32, result: Option<&mut Out<'_, u32>>) -> u32 {
    if key == 0 {
        return ERROR_INVALID_HANDLE;
    }
    let root = match map(key) {
        Ok(root) => root,
        Err(code) => {
            give(result, 0);
            return code;
        }
    };
    match nt::open_key(&attributes(root, path, false), access) {
        Ok(handle) => {
            give(result, handle);
            ERROR_SUCCESS
        }
        Err(status) => {
            give(result, 0);
            error(status)
        }
    }
}

/// The key `path` names below `key` for a call's own use (`key` itself for the empty path): its
/// NT handle, and the handle to close after when the call opened one.
fn subkey(key: u32, path: &Counted, access: u32) -> Result<(u32, Option<Opened>), u32> {
    if path.is_empty() {
        if key == 0 {
            return Err(ERROR_INVALID_HANDLE);
        }
        return map(key).map(|root| (root, None));
    }
    let mut handle = 0u32;
    let code = open_key(key, path, access, Some(&mut Out::from(&mut handle)));
    match code {
        ERROR_SUCCESS => Ok((handle, Some(Opened(handle)))),
        code => Err(code),
    }
}

/// RegDeleteKeyW's core: `path` below `key` deleted.
fn delete_key(key: u32, path: &Counted) -> u32 {
    let mut handle = 0u32;
    let code = open_key(key, path, DELETE, Some(&mut Out::from(&mut handle)));
    if code != ERROR_SUCCESS {
        return code;
    }
    let handle = Opened(handle);
    self::code(nt::delete_key(handle.0))
}

/// A subkey's name as NtEnumerateKey reads it: KEY_BASIC_INFORMATION and room for the longest
/// name.
#[repr(C, align(8))]
struct BasicName {
    bytes: [u8; BASIC_NAME + 2 * MAX_KEY_NAME + 2],
}

impl BasicName {
    /// The name's units.
    fn units(&self) -> &[u16] {
        let length = u32::from_le_bytes(self.bytes[12..16].try_into().unwrap()) as usize / 2;
        let length = length.min(MAX_KEY_NAME + 1);
        // SAFETY: the name's units, within the structure (8-aligned, so the units are aligned).
        unsafe { core::slice::from_raw_parts(self.bytes[BASIC_NAME..].as_ptr().cast(), length) }
    }
}

/// Subkey `index` of `key`'s name, or the error.
fn enum_key(key: u32, index: u32) -> Result<BasicName, u32> {
    if key == 0 {
        return Err(ERROR_INVALID_HANDLE);
    }
    let key = map(key)?;
    let mut name = BasicName {
        bytes: [0; BASIC_NAME + 2 * MAX_KEY_NAME + 2],
    };
    nt::enumerate_key(key, index, KEY_BASIC_INFORMATION, &mut name.bytes).map_err(error)?;
    Ok(name)
}

/// What a value query found: its error (ERROR_SUCCESS, ERROR_MORE_DATA when the data did not
/// fit, another for no value), its type and its data's size in bytes.
struct Found {
    code: u32,
    kind: u32,
    size: u32,
}

/// Query `name`'s value of the NT key `key` into `data` (none: the type and the size alone): the
/// data is written only when it fits whole.
fn query_value(key: u32, name: &Counted, data: Option<&mut [u8]>) -> Found {
    /// KEY_VALUE_PARTIAL_INFORMATION with room for short data.
    #[repr(C, align(8))]
    struct Partial([u8; PARTIAL_DATA + 256]);
    let mut partial = Partial([0; PARTIAL_DATA + 256]);
    let whole_here =
        match nt::query_value_key(key, name, KEY_VALUE_PARTIAL_INFORMATION, &mut partial.0) {
            Ok(_) => true,
            Err(NtStatus(STATUS_BUFFER_OVERFLOW)) => false,
            Err(status) => {
                return Found {
                    code: error(status),
                    kind: 0,
                    size: 0,
                }
            }
        };
    let word = |at: usize| u32::from_le_bytes(partial.0[at..at + 4].try_into().unwrap());
    let mut found = Found {
        code: ERROR_SUCCESS,
        kind: word(4),
        size: word(8),
    };
    let Some(data) = data else {
        return found;
    };
    if found.size as usize > data.len() {
        found.code = ERROR_MORE_DATA;
        return found;
    }
    let size = found.size as usize;
    if whole_here {
        if let Some(bytes) = partial.0.get(PARTIAL_DATA..PARTIAL_DATA + size) {
            data[..size].copy_from_slice(bytes);
            return found;
        }
    }
    // Data longer than the buffer above: read again, whole.
    let mut whole = match block(PARTIAL_DATA + size) {
        Ok(whole) => whole,
        Err(code) => {
            found.code = code;
            return found;
        }
    };
    match nt::query_value_key(key, name, KEY_VALUE_PARTIAL_INFORMATION, whole.bytes_mut()) {
        Ok(_) => {}
        // The value grew in between.
        Err(NtStatus(STATUS_BUFFER_OVERFLOW)) => {
            found.code = ERROR_MORE_DATA;
            return found;
        }
        Err(status) => {
            found.code = error(status);
            return found;
        }
    }
    data[..size].copy_from_slice(&whole.bytes()[PARTIAL_DATA..]);
    found
}

/// RegQueryValueExW's core over the NT key `key`: the type, the size and, when it fits, the
/// data. A failure leaves the type, and the size when data was given, as they were; with no data
/// the size is zeroed.
fn query_value_w(
    key: u32,
    name: &Counted,
    kind: Option<&mut Out<'_, u32>>,
    data: Option<&mut [u8]>,
    size: Option<&mut Out<'_, u32>>,
) -> u32 {
    let no_data = data.is_none();
    let found = query_value(key, name, data);
    if found.code != ERROR_SUCCESS && found.code != ERROR_MORE_DATA {
        if no_data {
            give(size, 0);
        }
        return found.code;
    }
    give(kind, found.kind);
    give(size, found.size);
    found.code
}

/// RegQueryValueExA's core over the NT key `key`: as the W core, a string value converted to the
/// ANSI code page in the caller's buffer, its sizes the ANSI ones.
fn query_value_a(
    key: u32,
    name: &Counted,
    kind: Option<&mut Out<'_, u32>>,
    mut data: Option<&mut [u8]>,
    size: Option<&mut Out<'_, u32>>,
) -> u32 {
    let found = query_value(key, name, data.as_deref_mut());
    if found.code != ERROR_SUCCESS && found.code != ERROR_MORE_DATA {
        if data.is_none() {
            give(size, 0);
        }
        return found.code;
    }
    if !is_text(found.kind) {
        give(kind, found.kind);
        give(size, found.size);
        return found.code;
    }
    // The Unicode text, in a block of our own: copied from the caller's buffer when it was read
    // there (its conversion overwrites it from the start), read again otherwise.
    let mut text = match block(found.size as usize) {
        Ok(text) => text,
        Err(code) => return code,
    };
    match data.as_deref() {
        Some(data) if found.code == ERROR_SUCCESS => {
            text.bytes_mut()
                .copy_from_slice(&data[..found.size as usize]);
        }
        _ => {
            let again = query_value(key, name, Some(text.bytes_mut()));
            if again.code != ERROR_SUCCESS {
                return again.code;
            }
        }
    }
    let ansi = nt::unicode_to_multi_byte_size(text.units());
    let code = match data {
        None => ERROR_SUCCESS,
        Some(data) if ansi as usize > data.len() => ERROR_MORE_DATA,
        Some(data) => {
            nt::unicode_to_multi_byte(&mut data[..ansi as usize], text.units());
            ERROR_SUCCESS
        }
    };
    give(kind, found.kind);
    give(size, ansi);
    code
}

/// RegSetValueExW's core over the NT key `key`: a string value without its terminator gets one.
fn set_value_w(key: u32, name: &Counted, kind: u32, data: &[u8]) -> u32 {
    let unterminated = is_text(kind)
        && data.len() >= 2
        && data.len().is_multiple_of(2)
        && data[data.len() - 2..] != [0, 0];
    let terminated;
    let data = if unterminated {
        let mut block = match block(data.len() + 2) {
            Ok(block) => block,
            Err(code) => return code,
        };
        // The block is zeroed: the terminator is already there, past the data.
        block.bytes_mut()[..data.len()].copy_from_slice(data);
        terminated = block;
        terminated.bytes()
    } else {
        data
    };
    code(nt::set_value_key(key, name, kind, data))
}

/// RegSetValueExA's core over the NT key `key`: string data converted to Unicode first.
fn set_value_a(key: u32, name: &Counted, kind: u32, data: &[u8]) -> u32 {
    if !is_text(kind) {
        return set_value_w(key, name, kind, data);
    }
    let mut wide = match block(2 * data.len()) {
        Ok(wide) => wide,
        Err(code) => return code,
    };
    let units = nt::multi_byte_to_unicode(wide.units_mut(), data);
    set_value_w(key, name, kind, &wide.bytes()[..2 * units])
}

// --- The exports ---------------------------------------------------------------------------------

/// RegCloseKey: the handle closed; a predefined key's kept handle closed (the next use opens it
/// again).
#[unsafe(export_name = "f2k_export_RegCloseKey")]
pub unsafe extern "system" fn reg_close_key(key: u32) -> u32 {
    if key == 0 {
        return ERROR_INVALID_HANDLE;
    }
    if let Some(index) = predefined(key) {
        let kept = PREDEFINED[index].swap(0, Ordering::AcqRel);
        if kept != 0 {
            let _ = nt::close(kept);
        }
        return ERROR_SUCCESS;
    }
    code(nt::close(key))
}

/// RegCreateKeyExW: the key `sub_key` names below `key`, made with every missing key above it,
/// opened when it exists; the handle (NULL on a failure) and, when asked, the disposition.
///
/// # Safety
///
/// The strings are NUL-terminated (the class may be null); the security attributes readable or
/// null; the out parameters writable or null.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_RegCreateKeyExW")]
pub unsafe extern "system" fn reg_create_key_ex_w(
    key: u32,
    sub_key: *const u16,
    _reserved: u32,
    class: *const u16,
    options: u32,
    access: u32,
    security: *const SecurityAttributes,
    result: *mut u32,
    disposition: *mut u32,
) -> u32 {
    // SAFETY: the caller's strings, structure and out parameters.
    let (path, class_units, inherit, mut result, mut disposition) = unsafe {
        (
            wide_text(sub_key),
            wide_text(class),
            inherits(security),
            Out::optional(result),
            Out::optional(disposition),
        )
    };
    let class_name = Counted::new(class_units);
    create_key(
        key,
        &Counted::new(path),
        (!class.is_null()).then_some(&class_name),
        options,
        access,
        inherit,
        result.as_mut(),
        disposition.as_mut(),
    )
}

/// RegCreateKeyExA: RegCreateKeyExW of the names converted.
///
/// # Safety
///
/// As RegCreateKeyExW's.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_RegCreateKeyExA")]
pub unsafe extern "system" fn reg_create_key_ex_a(
    key: u32,
    sub_key: *const u8,
    _reserved: u32,
    class: *const u8,
    options: u32,
    access: u32,
    security: *const SecurityAttributes,
    result: *mut u32,
    disposition: *mut u32,
) -> u32 {
    // SAFETY: the caller's strings, structure and out parameters.
    let (path, class_text, inherit, mut result, mut disposition) = unsafe {
        (
            ansi_text(sub_key),
            ansi_text(class),
            inherits(security),
            Out::optional(result),
            Out::optional(disposition),
        )
    };
    let (path, class_name) = match (wide(path), wide(class_text)) {
        (Ok(path), Ok(class)) => (path, class),
        (Err(code), _) | (_, Err(code)) => return code,
    };
    let class_name = class_name.counted();
    create_key(
        key,
        &path.counted(),
        (!class.is_null()).then_some(&class_name),
        options,
        access,
        inherit,
        result.as_mut(),
        disposition.as_mut(),
    )
}

/// Whether the caller's SECURITY_ATTRIBUTES at `security` (none for null) has the handle
/// inherited.
///
/// # Safety
///
/// `security` is null or readable (at any alignment).
unsafe fn inherits(security: *const SecurityAttributes) -> bool {
    // SAFETY: the caller's contract; the structure read unaligned.
    !security.is_null() && unsafe { security.read_unaligned() }.inherit_handle != 0
}

/// RegOpenKeyExW: the key `sub_key` names below `key` (a new handle to `key`'s own key for none);
/// the handle, NULL on a failure.
///
/// # Safety
///
/// The string is NUL-terminated or null; the result writable or null.
#[unsafe(export_name = "f2k_export_RegOpenKeyExW")]
pub unsafe extern "system" fn reg_open_key_ex_w(
    key: u32,
    sub_key: *const u16,
    _options: u32,
    access: u32,
    result: *mut u32,
) -> u32 {
    // SAFETY: the caller's string and out parameter.
    let (path, mut result) = unsafe { (wide_text(sub_key), Out::optional(result)) };
    open_key(key, &Counted::new(path), access, result.as_mut())
}

/// RegOpenKeyExA: RegOpenKeyExW of the name converted.
///
/// # Safety
///
/// As RegOpenKeyExW's.
#[unsafe(export_name = "f2k_export_RegOpenKeyExA")]
pub unsafe extern "system" fn reg_open_key_ex_a(
    key: u32,
    sub_key: *const u8,
    _options: u32,
    access: u32,
    result: *mut u32,
) -> u32 {
    // SAFETY: the caller's string and out parameter.
    let (path, mut result) = unsafe { (ansi_text(sub_key), Out::optional(result)) };
    match wide(path) {
        Ok(path) => open_key(key, &path.counted(), access, result.as_mut()),
        Err(code) => code,
    }
}

/// RegOpenKey's answer for no subkey (a null or empty name): `key` itself, the same handle.
fn open_key_itself(key: u32, result: Option<&mut Out<'_, u32>>) -> u32 {
    if key == 0 {
        return ERROR_INVALID_HANDLE;
    }
    give(result, key);
    ERROR_SUCCESS
}

/// RegOpenKeyW: RegOpenKeyExW with every right the key allows; for no subkey, `key` itself.
///
/// # Safety
///
/// As RegOpenKeyExW's.
#[unsafe(export_name = "f2k_export_RegOpenKeyW")]
pub unsafe extern "system" fn reg_open_key_w(
    key: u32,
    sub_key: *const u16,
    result: *mut u32,
) -> u32 {
    // SAFETY: the caller's string and out parameter.
    let (path, mut result) = unsafe { (wide_text(sub_key), Out::optional(result)) };
    if path.is_empty() {
        return open_key_itself(key, result.as_mut());
    }
    open_key(key, &Counted::new(path), MAXIMUM_ALLOWED, result.as_mut())
}

/// RegOpenKeyA: RegOpenKeyW of the name converted.
///
/// # Safety
///
/// As RegOpenKeyExW's.
#[unsafe(export_name = "f2k_export_RegOpenKeyA")]
pub unsafe extern "system" fn reg_open_key_a(
    key: u32,
    sub_key: *const u8,
    result: *mut u32,
) -> u32 {
    // SAFETY: the caller's string and out parameter.
    let (path, mut result) = unsafe { (ansi_text(sub_key), Out::optional(result)) };
    let path = match wide(path) {
        Ok(path) => path,
        Err(code) => return code,
    };
    let path = path.counted();
    if path.is_empty() {
        return open_key_itself(key, result.as_mut());
    }
    open_key(key, &path, MAXIMUM_ALLOWED, result.as_mut())
}

/// RegDeleteKeyW: the key `sub_key` names below `key` deleted (ERROR_ACCESS_DENIED for one with
/// subkeys); its handles stay open, answering ERROR_KEY_DELETED.
///
/// # Safety
///
/// The string is NUL-terminated.
#[unsafe(export_name = "f2k_export_RegDeleteKeyW")]
pub unsafe extern "system" fn reg_delete_key_w(key: u32, sub_key: *const u16) -> u32 {
    // SAFETY: the caller's string.
    delete_key(key, &Counted::new(unsafe { wide_text(sub_key) }))
}

/// RegDeleteKeyA: RegDeleteKeyW of the name converted.
///
/// # Safety
///
/// As RegDeleteKeyW's.
#[unsafe(export_name = "f2k_export_RegDeleteKeyA")]
pub unsafe extern "system" fn reg_delete_key_a(key: u32, sub_key: *const u8) -> u32 {
    // SAFETY: the caller's string.
    match wide(unsafe { ansi_text(sub_key) }) {
        Ok(path) => delete_key(key, &path.counted()),
        Err(code) => code,
    }
}

/// RegEnumKeyW: subkey `index`'s name into `name`, `units` long, with its terminator, the subkeys
/// in their names' order; ERROR_MORE_DATA (nothing written) when it does not fit,
/// ERROR_NO_MORE_ITEMS past the last.
///
/// # Safety
///
/// `name` holds `units` units (at any alignment).
#[unsafe(export_name = "f2k_export_RegEnumKeyW")]
pub unsafe extern "system" fn reg_enum_key_w(
    key: u32,
    index: u32,
    name: *mut u16,
    units: u32,
) -> u32 {
    let found = match enum_key(key, index) {
        Ok(found) => found,
        Err(code) => return code,
    };
    let text = found.units();
    if (units as usize) < text.len() + 1 {
        return ERROR_MORE_DATA;
    }
    // SAFETY: the caller's buffer holds `units` units, at least the name's and its terminator's.
    let Some(buffer) = (unsafe { caller_bytes_mut(name.cast(), 2 * (text.len() + 1)) }) else {
        return ERROR_NOACCESS;
    };
    for (pair, unit) in buffer
        .as_chunks_mut()
        .0
        .iter_mut()
        .zip(text.iter().chain([&0]))
    {
        *pair = unit.to_le_bytes();
    }
    ERROR_SUCCESS
}

/// RegEnumKeyA: RegEnumKeyW's name converted into `name`, `bytes` long: when it does not fit, what
/// fits is written, terminated, and the answer is ERROR_MORE_DATA.
///
/// # Safety
///
/// `name` holds `bytes` bytes.
#[unsafe(export_name = "f2k_export_RegEnumKeyA")]
pub unsafe extern "system" fn reg_enum_key_a(
    key: u32,
    index: u32,
    name: *mut u8,
    bytes: u32,
) -> u32 {
    let found = match enum_key(key, index) {
        Ok(found) => found,
        Err(code) => return code,
    };
    // SAFETY: the caller's buffer, of its length (what a counted string's room holds of it).
    let Some(buffer) = (unsafe { caller_bytes_mut(name, bytes.min(0xFFFF) as usize) }) else {
        return ERROR_NOACCESS;
    };
    code(nt::unicode_to_ansi_string(
        &Counted::new(found.units()),
        buffer,
    ))
}

/// The caller's data buffer of a value query and its size: the size's out parameter, and the
/// buffer of the size it holds (none for null data: the call answers the size alone).
///
/// # Safety
///
/// `size` is null or a writable dword; non-null `data` holds the bytes `*size` says.
unsafe fn query_buffer<'a>(
    data: *mut u8,
    size: *mut u32,
) -> (Option<&'a mut [u8]>, Option<Out<'a, u32>>) {
    // SAFETY: the caller's contract.
    let size = unsafe { Out::optional(size) };
    let room = size.as_ref().map_or(0, Out::get);
    let data = if data.is_null() {
        None
    } else {
        // SAFETY: the caller's contract: non-null data of the size's bytes.
        unsafe { caller_bytes_mut(data, room as usize) }
    };
    (data, size)
}

/// RegQueryValueExW: `name`'s value of `key` (the default value for a null or empty name): its
/// type, its size and, when it fits, its data (ERROR_MORE_DATA, the size told, when it does not).
/// Data without a size is ERROR_INVALID_PARAMETER.
///
/// # Safety
///
/// The name is NUL-terminated or null; `data` holds `*size` bytes; the out parameters writable or
/// null.
#[unsafe(export_name = "f2k_export_RegQueryValueExW")]
pub unsafe extern "system" fn reg_query_value_ex_w(
    key: u32,
    name: *const u16,
    _reserved: *mut u32,
    kind: *mut u32,
    data: *mut u8,
    size: *mut u32,
) -> u32 {
    if !data.is_null() && size.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    if key == 0 {
        return ERROR_INVALID_HANDLE;
    }
    let key = match map(key) {
        Ok(key) => key,
        Err(code) => return code,
    };
    // SAFETY: the caller's string, buffer and out parameters.
    let (name, mut kind, (data, mut size)) = unsafe {
        (
            wide_text(name),
            Out::optional(kind),
            query_buffer(data, size),
        )
    };
    query_value_w(key, &Counted::new(name), kind.as_mut(), data, size.as_mut())
}

/// RegQueryValueExA: RegQueryValueExW of the name converted, a string value in the ANSI code page
/// (its sizes the ANSI ones).
///
/// # Safety
///
/// As RegQueryValueExW's.
#[unsafe(export_name = "f2k_export_RegQueryValueExA")]
pub unsafe extern "system" fn reg_query_value_ex_a(
    key: u32,
    name: *const u8,
    _reserved: *mut u32,
    kind: *mut u32,
    data: *mut u8,
    size: *mut u32,
) -> u32 {
    if !data.is_null() && size.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    if key == 0 {
        return ERROR_INVALID_HANDLE;
    }
    let key = match map(key) {
        Ok(key) => key,
        Err(code) => return code,
    };
    // SAFETY: the caller's string, buffer and out parameters.
    let (name, mut kind, (data, mut size)) = unsafe {
        (
            ansi_text(name),
            Out::optional(kind),
            query_buffer(data, size),
        )
    };
    match wide(name) {
        Ok(name) => query_value_a(key, &name.counted(), kind.as_mut(), data, size.as_mut()),
        Err(code) => code,
    }
}

/// RegSetValueExW: `name`'s value of `key` (the default value for a null or empty name) set to
/// `size` bytes of type `kind`.
///
/// # Safety
///
/// The name is NUL-terminated or null; `data` holds `size` bytes.
#[unsafe(export_name = "f2k_export_RegSetValueExW")]
pub unsafe extern "system" fn reg_set_value_ex_w(
    key: u32,
    name: *const u16,
    _reserved: u32,
    kind: u32,
    data: *const u8,
    size: u32,
) -> u32 {
    if key == 0 {
        return ERROR_INVALID_HANDLE;
    }
    let key = match map(key) {
        Ok(key) => key,
        Err(code) => return code,
    };
    // SAFETY: the caller's string and data.
    let (name, data) = unsafe { (wide_text(name), caller_bytes(data, size as usize)) };
    let Some(data) = data else {
        return ERROR_NOACCESS;
    };
    set_value_w(key, &Counted::new(name), kind, data)
}

/// RegSetValueExA: RegSetValueExW of the name converted, string data converted to Unicode.
///
/// # Safety
///
/// As RegSetValueExW's.
#[unsafe(export_name = "f2k_export_RegSetValueExA")]
pub unsafe extern "system" fn reg_set_value_ex_a(
    key: u32,
    name: *const u8,
    _reserved: u32,
    kind: u32,
    data: *const u8,
    size: u32,
) -> u32 {
    if key == 0 {
        return ERROR_INVALID_HANDLE;
    }
    let key = match map(key) {
        Ok(key) => key,
        Err(code) => return code,
    };
    // SAFETY: the caller's string and data.
    let (name, data) = unsafe { (ansi_text(name), caller_bytes(data, size as usize)) };
    let Some(data) = data else {
        return ERROR_NOACCESS;
    };
    match wide(name) {
        Ok(name) => set_value_a(key, &name.counted(), kind, data),
        Err(code) => code,
    }
}

/// RegSetValue's core: the default value of `path` below `key` (made with every missing key above
/// it; `key` itself for the empty path) set to the Unicode text `text`, its terminator included.
fn set_default(key: u32, path: &Counted, text: &[u8]) -> u32 {
    let (target, _opened) = if path.is_empty() {
        if key == 0 {
            return ERROR_INVALID_HANDLE;
        }
        match map(key) {
            Ok(target) => (target, None),
            Err(code) => return code,
        }
    } else {
        let mut handle = 0u32;
        let code = create_key(
            key,
            path,
            None,
            0,
            KEY_SET_VALUE,
            false,
            Some(&mut Out::from(&mut handle)),
            None,
        );
        if code != ERROR_SUCCESS {
            return code;
        }
        (handle, Some(Opened(handle)))
    };
    set_value_w(target, &Counted::new(&[]), REG_SZ, text)
}

/// RegSetValueW: the default value of `sub_key` below `key` set to the string, REG_SZ alone
/// (another type is ERROR_INVALID_PARAMETER); the size is the string's own, its terminator
/// counted (the documented cbData is ignored).
///
/// # Safety
///
/// The strings are NUL-terminated (the subkey may be null).
#[unsafe(export_name = "f2k_export_RegSetValueW")]
pub unsafe extern "system" fn reg_set_value_w(
    key: u32,
    sub_key: *const u16,
    kind: u32,
    text: *const u16,
    _size: u32,
) -> u32 {
    if kind != REG_SZ {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: the caller's strings.
    let (path, value) = unsafe { (wide_text(sub_key), wide_text_bytes(text)) };
    let Some(value) = value else {
        return ERROR_NOACCESS;
    };
    set_default(key, &Counted::new(path), value)
}

/// RegSetValueA: RegSetValueW of the name and the string converted.
///
/// # Safety
///
/// As RegSetValueW's.
#[unsafe(export_name = "f2k_export_RegSetValueA")]
pub unsafe extern "system" fn reg_set_value_a(
    key: u32,
    sub_key: *const u8,
    kind: u32,
    text: *const u8,
    _size: u32,
) -> u32 {
    if kind != REG_SZ {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: the caller's strings.
    let (path, value) = unsafe { (ansi_text(sub_key), ansi_text(text)) };
    let (path, value) = match (wide(path), wide(value)) {
        (Ok(path), Ok(value)) => (path, value),
        (Err(code), _) | (_, Err(code)) => return code,
    };
    set_default(key, &path.counted(), value.terminated_bytes())
}

/// RegQueryValue's core: the default value of `path` below `key` (`key` itself for the empty
/// path) through `query` (the W or the A form), into `data`, its size `size`'s. A key with no
/// default value answers the empty string (`unit` bytes, its terminator); one of a type other
/// than REG_SZ is ERROR_INVALID_DATA, its data written all the same.
fn query_default(
    key: u32,
    path: &Counted,
    mut data: Option<&mut [u8]>,
    mut size: Option<&mut Out<'_, u32>>,
    unit: u32,
    query: QueryValue,
) -> u32 {
    let (target, _opened) = match subkey(key, path, KEY_QUERY_VALUE) {
        Ok(target) => target,
        Err(code) => return code,
    };
    let mut kind = 0u32;
    let code = query(
        target,
        &Counted::new(&[]),
        Some(&mut Out::from(&mut kind)),
        data.as_deref_mut(),
        size.as_deref_mut(),
    );
    match code {
        ERROR_FILE_NOT_FOUND => {
            if let Some(data) = data {
                if data.len() < unit as usize {
                    give(size, unit);
                    return ERROR_MORE_DATA;
                }
                data[..unit as usize].fill(0);
            }
            give(size, unit);
            ERROR_SUCCESS
        }
        ERROR_SUCCESS if kind != REG_SZ => ERROR_INVALID_DATA,
        code => code,
    }
}

/// A value query's core: RegQueryValueExW's or RegQueryValueExA's.
type QueryValue = fn(
    u32,
    &Counted,
    Option<&mut Out<'_, u32>>,
    Option<&mut [u8]>,
    Option<&mut Out<'_, u32>>,
) -> u32;

/// RegQueryValueW: the default value of `sub_key` below `key` (see `query_default`).
///
/// # Safety
///
/// The subkey is NUL-terminated or null; `data` holds `*size` bytes.
#[unsafe(export_name = "f2k_export_RegQueryValueW")]
pub unsafe extern "system" fn reg_query_value_w(
    key: u32,
    sub_key: *const u16,
    data: *mut u16,
    size: *mut u32,
) -> u32 {
    if !data.is_null() && size.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: the caller's string, buffer and size.
    let (path, (data, mut size)) = unsafe { (wide_text(sub_key), query_buffer(data.cast(), size)) };
    query_default(
        key,
        &Counted::new(path),
        data,
        size.as_mut(),
        2,
        query_value_w,
    )
}

/// RegQueryValueA: RegQueryValueW of the name converted, the string in the ANSI code page.
///
/// # Safety
///
/// As RegQueryValueW's.
#[unsafe(export_name = "f2k_export_RegQueryValueA")]
pub unsafe extern "system" fn reg_query_value_a(
    key: u32,
    sub_key: *const u8,
    data: *mut u8,
    size: *mut u32,
) -> u32 {
    if !data.is_null() && size.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: the caller's string, buffer and size.
    let (path, (data, mut size)) = unsafe { (ansi_text(sub_key), query_buffer(data, size)) };
    match wide(path) {
        Ok(path) => query_default(key, &path.counted(), data, size.as_mut(), 1, query_value_a),
        Err(code) => code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_predefined_keys_are_seven() {
        assert_eq!(predefined(0x8000_0000), Some(0));
        assert_eq!(predefined(0x8000_0001), Some(1));
        assert_eq!(predefined(0x8000_0006), Some(6));
        assert_eq!(predefined(0x8000_0007), None);
        assert_eq!(predefined(0x7FFF_FFFC), None);
        assert_eq!(predefined(0), None);
        assert_eq!(predefined_path(2), Some(&b"\\Registry\\Machine"[..]));
        assert_eq!(predefined_path(4), None, "HKEY_PERFORMANCE_DATA has no key");
    }

    #[test]
    fn the_calls_check_their_arguments_first() {
        let mut data = [0u8; 4];
        // SAFETY: the tests' own buffers.
        unsafe {
            assert_eq!(
                reg_query_value_ex_w(
                    0x8000_0001,
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    data.as_mut_ptr(),
                    core::ptr::null_mut()
                ),
                ERROR_INVALID_PARAMETER,
                "data without a size"
            );
            assert_eq!(reg_close_key(0), ERROR_INVALID_HANDLE);
            assert_eq!(
                reg_close_key(0x8000_0002),
                ERROR_SUCCESS,
                "a predefined key closes"
            );
            assert_eq!(
                reg_set_value_w(0x8000_0001, core::ptr::null(), 4, [0u16].as_ptr(), 0),
                ERROR_INVALID_PARAMETER,
                "RegSetValue takes REG_SZ alone"
            );
            let mut result = 0x00F2_F2F0u32;
            assert_eq!(
                reg_open_key_ex_w(0, [0u16].as_ptr(), 0, 0, &mut result),
                ERROR_INVALID_HANDLE
            );
            assert_eq!(result, 0x00F2_F2F0, "a null key leaves the result alone");
            assert_eq!(
                reg_open_key_w(0x1234, core::ptr::null(), &mut result),
                ERROR_SUCCESS
            );
            assert_eq!(result, 0x1234, "no subkey: the same handle");
        }
    }

    #[test]
    fn a_wide_string_converts_and_goes() {
        // SAFETY: a NUL-terminated string.
        let wide = wide(unsafe { ansi_text(b"Software\\F2K\0".as_ptr()) }).unwrap();
        assert_eq!(
            String::from_utf16(wide.counted().units()).unwrap(),
            "Software\\F2K"
        );
        assert_eq!(wide.terminated_bytes().len(), 2 * 12 + 2);
        assert_eq!(wide.terminated_bytes()[24..], [0, 0]);
        // SAFETY: null is the empty string.
        let empty = super::wide(unsafe { ansi_text(core::ptr::null()) }).unwrap();
        assert!(empty.counted().is_empty());
        assert_eq!(empty.terminated_bytes(), [0, 0]);
    }

    /// An out parameter is read and written at any alignment; a buffer at a null address with a
    /// length is none, with no length the empty one.
    #[test]
    fn the_callers_places_convert_once() {
        let mut bytes = [0u8; 9];
        // SAFETY: a dword's place at an odd address in the local buffer.
        let mut out = unsafe { Out::optional(bytes[1..].as_mut_ptr().cast::<u32>()) }.unwrap();
        out.set(0x1122_3344);
        assert_eq!(out.get(), 0x1122_3344);
        assert_eq!(bytes[1..5], [0x44, 0x33, 0x22, 0x11]);
        // SAFETY: null.
        assert!(unsafe { Out::<u32>::optional(core::ptr::null_mut()) }.is_none());
        // SAFETY: null addresses, with and without a length.
        unsafe {
            assert!(caller_bytes(core::ptr::null(), 4).is_none());
            assert_eq!(caller_bytes(core::ptr::null(), 0), Some(&[][..]));
            assert!(caller_bytes_mut(core::ptr::null_mut(), 0).is_some());
        }
    }

    /// RegSetValueExW of data at a null address with a size cannot reach it.
    #[test]
    fn data_out_of_reach_is_no_access() {
        // SAFETY: a null name and data at a null address.
        let code =
            unsafe { reg_set_value_ex_w(0x1234, core::ptr::null(), 0, 4, core::ptr::null(), 4) };
        assert_eq!(code, ERROR_NOACCESS);
    }
}
