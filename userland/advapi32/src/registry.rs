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

use core::sync::atomic::{AtomicU32, Ordering};

use crate::imports::{self as nt, AnsiString, ObjectAttributes, UnicodeString};

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const ERROR_INVALID_DATA: u32 = 13;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_MORE_DATA: u32 = 234;

const STATUS_SUCCESS: u32 = 0;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

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

/// Whether a value's data is text.
pub fn is_text(kind: u32) -> bool {
    matches!(kind, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ)
}

/// The predefined key `key` is, by its place (HKEY_CLASSES_ROOT first).
pub fn predefined(key: u32) -> Option<usize> {
    let index = key.wrapping_sub(PREDEFINED_FIRST) as usize;
    (index < PREDEFINED_COUNT).then_some(index)
}

/// The Win32 error a status maps to.
fn error(status: u32) -> u32 {
    if status == STATUS_SUCCESS {
        return ERROR_SUCCESS;
    }
    // SAFETY: a plain mapping.
    unsafe { nt::RtlNtStatusToDosError(status) }
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
fn open_predefined(index: usize) -> Result<u32, u32> {
    let mut handle = 0u32;
    let status = if index == 1 {
        // SAFETY: the handle slot is ours.
        unsafe { nt::RtlOpenCurrentUser(MAXIMUM_ALLOWED, &mut handle) }
    } else {
        let Some(path) = predefined_path(index) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let mut units = [0u16; 80];
        for (unit, &byte) in units.iter_mut().zip(path) {
            *unit = byte as u16;
        }
        let name = counted_units(&units[..path.len()]);
        let attributes = attributes(0, &name, false);
        // SAFETY: the attributes and the name live across the call.
        unsafe { nt::NtOpenKey(&mut handle, MAXIMUM_ALLOWED, &attributes) }
    };
    if status == STATUS_SUCCESS {
        Ok(handle)
    } else {
        Err(status)
    }
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
            // SAFETY: our own handle.
            unsafe { nt::NtClose(opened) };
            Ok(other)
        }
    }
}

/// A counted string over `units` (no buffer for none).
fn counted_units(units: &[u16]) -> UnicodeString {
    let bytes = (2 * units.len()).min(0xFFFC) as u16;
    UnicodeString {
        length: bytes,
        maximum_length: bytes,
        buffer: if units.is_empty() {
            core::ptr::null_mut()
        } else {
            units.as_ptr() as *mut u16
        },
    }
}

/// A counted string over the NUL-terminated string at `text` (the empty string for null).
///
/// # Safety
///
/// `text` is null or NUL-terminated.
unsafe fn counted(text: *const u16) -> UnicodeString {
    if text.is_null() {
        return counted_units(&[]);
    }
    let mut length = 0;
    // SAFETY: the caller's NUL-terminated string.
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: the string's units, up to its terminator.
    counted_units(unsafe { core::slice::from_raw_parts(text, length) })
}

/// An ANSI string converted to Unicode, its buffer the process heap's until it is dropped.
struct Wide {
    string: UnicodeString,
}

impl Wide {
    /// The NUL-terminated ANSI string at `text` (the empty string for null), converted: none when
    /// the heap has no room (ERROR_NOT_ENOUGH_MEMORY).
    ///
    /// # Safety
    ///
    /// `text` is null or NUL-terminated.
    unsafe fn of(text: *const u8) -> Result<Wide, u32> {
        let mut length = 0;
        if !text.is_null() {
            // SAFETY: the caller's NUL-terminated string.
            while unsafe { *text.add(length) } != 0 {
                length += 1;
            }
        }
        // SAFETY: the string's bytes.
        unsafe { Self::of_bytes(text, length) }
    }

    /// `length` bytes at `text` converted (their counted form holds 65534 at most).
    ///
    /// # Safety
    ///
    /// `text` holds `length` bytes (null for none).
    unsafe fn of_bytes(text: *const u8, length: usize) -> Result<Wide, u32> {
        let length = length.min(0xFFFE);
        let source = AnsiString {
            length: length as u16,
            maximum_length: length as u16,
            buffer: text as *mut u8,
        };
        let mut string = counted_units(&[]);
        // SAFETY: the source holds its length; the destination is allocated.
        let status = unsafe { nt::RtlAnsiStringToUnicodeString(&mut string, &source, 1) };
        if status != STATUS_SUCCESS {
            return Err(if status == STATUS_NO_MEMORY {
                ERROR_NOT_ENOUGH_MEMORY
            } else {
                error(status)
            });
        }
        Ok(Wide { string })
    }
}

impl Drop for Wide {
    fn drop(&mut self) {
        // SAFETY: the string RtlAnsiStringToUnicodeString allocated.
        unsafe { nt::RtlFreeUnicodeString(&mut self.string) };
    }
}

/// A block of the process heap, freed when dropped.
struct Block {
    at: *mut u8,
}

impl Block {
    /// `size` bytes (at least one): none when the heap has no room.
    fn new(size: usize) -> Result<Block, u32> {
        // SAFETY: a plain allocation.
        let at = unsafe { nt::RtlAllocateHeap(nt::process_heap(), 0, size.max(1)) };
        if at.is_null() {
            Err(ERROR_NOT_ENOUGH_MEMORY)
        } else {
            Ok(Block { at })
        }
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        // SAFETY: our own block.
        unsafe { nt::RtlFreeHeap(nt::process_heap(), 0, self.at) };
    }
}

/// The OBJECT_ATTRIBUTES naming `name` below `root` (zero: an absolute name).
fn attributes(root: u32, name: &UnicodeString, inherit: bool) -> ObjectAttributes {
    ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: root,
        object_name: name,
        attributes: OBJ_CASE_INSENSITIVE | if inherit { OBJ_INHERIT } else { 0 },
        security_descriptor: core::ptr::null(),
        security_quality_of_service: core::ptr::null(),
    }
}

/// Write `value` where `at` points, when it points anywhere.
fn put<T>(at: *mut T, value: T) {
    if !at.is_null() {
        // SAFETY: the caller's out parameter.
        unsafe { at.write(value) };
    }
}

/// A handle the calls opened for themselves, closed when dropped.
struct Opened(u32);

impl Drop for Opened {
    fn drop(&mut self) {
        // SAFETY: our own handle.
        unsafe { nt::NtClose(self.0) };
    }
}

// --- The W core ----------------------------------------------------------------------------------

/// Create `path` below the NT key `root` key by key, each missing one made, the last with
/// `class` and `access`: what RegCreateKeyEx does once the whole path's create found a key on the
/// way missing. The last key's handle and disposition, or the status.
fn create_levels(
    root: u32,
    path: &UnicodeString,
    class: *const UnicodeString,
    options: u32,
    access: u32,
    inherit: bool,
) -> Result<(u32, u32), u32> {
    // SAFETY: the path's units, as counted.
    let units = unsafe { core::slice::from_raw_parts(path.buffer, path.length as usize / 2) };
    let units = units.strip_suffix(&[b'\\' as u16]).unwrap_or(units);
    let mut parent: Option<Opened> = None;
    let mut names = units.split(|&unit| unit == b'\\' as u16).peekable();
    while let Some(name) = names.next() {
        let last = names.peek().is_none();
        let name = counted_units(name);
        let at = parent.as_ref().map_or(root, |parent| parent.0);
        let attributes = attributes(at, &name, last && inherit);
        let (mut handle, mut disposition) = (0u32, 0u32);
        // SAFETY: the attributes, the name and the class live across the call.
        let status = unsafe {
            nt::NtCreateKey(
                &mut handle,
                if last { access } else { MAXIMUM_ALLOWED },
                &attributes,
                0,
                if last { class } else { core::ptr::null() },
                options,
                &mut disposition,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        if last {
            return Ok((handle, disposition));
        }
        parent = Some(Opened(handle));
    }
    Err(STATUS_OBJECT_NAME_NOT_FOUND)
}

/// RegCreateKeyExW's core: `path` below `key`, made with every missing key above it.
#[allow(clippy::too_many_arguments)]
fn create_key(
    key: u32,
    path: &UnicodeString,
    class: Option<&UnicodeString>,
    options: u32,
    access: u32,
    security: *const u32,
    result: *mut u32,
    disposition: *mut u32,
) -> u32 {
    if key == 0 {
        return ERROR_INVALID_HANDLE;
    }
    let root = match map(key) {
        Ok(root) => root,
        Err(code) => {
            put(result, 0);
            return code;
        }
    };
    // SECURITY_ATTRIBUTES: nLength, lpSecurityDescriptor, bInheritHandle.
    // SAFETY: the caller's structure, when given.
    let inherit = !security.is_null() && unsafe { *security.add(2) } != 0;
    let class = class.map_or(core::ptr::null(), |class| class as *const UnicodeString);
    let attributes = attributes(root, path, inherit);
    let (mut handle, mut outcome) = (0u32, 0u32);
    // SAFETY: the attributes, the path and the class live across the call.
    let mut status = unsafe {
        nt::NtCreateKey(
            &mut handle,
            access,
            &attributes,
            0,
            class,
            options,
            &mut outcome,
        )
    };
    if status == STATUS_OBJECT_NAME_NOT_FOUND {
        status = match create_levels(root, path, class, options, access, inherit) {
            Ok((made, how)) => {
                (handle, outcome) = (made, how);
                STATUS_SUCCESS
            }
            Err(status) => status,
        };
    }
    if status != STATUS_SUCCESS {
        put(result, 0);
        return error(status);
    }
    put(result, handle);
    put(disposition, outcome);
    ERROR_SUCCESS
}

/// RegOpenKeyExW's core: `path` below `key` opened with `access`.
fn open_key(key: u32, path: &UnicodeString, access: u32, result: *mut u32) -> u32 {
    if key == 0 {
        return ERROR_INVALID_HANDLE;
    }
    let root = match map(key) {
        Ok(root) => root,
        Err(code) => {
            put(result, 0);
            return code;
        }
    };
    let attributes = attributes(root, path, false);
    let mut handle = 0u32;
    // SAFETY: the attributes and the path live across the call.
    let status = unsafe { nt::NtOpenKey(&mut handle, access, &attributes) };
    if status != STATUS_SUCCESS {
        put(result, 0);
        return error(status);
    }
    put(result, handle);
    ERROR_SUCCESS
}

/// The key `path` names below `key` for a call's own use (`key` itself for the empty path): its
/// NT handle, and the handle to close after when the call opened one.
fn subkey(key: u32, path: &UnicodeString, access: u32) -> Result<(u32, Option<Opened>), u32> {
    if path.length == 0 {
        if key == 0 {
            return Err(ERROR_INVALID_HANDLE);
        }
        return map(key).map(|root| (root, None));
    }
    let mut handle = 0u32;
    match open_key(key, path, access, &mut handle) {
        ERROR_SUCCESS => Ok((handle, Some(Opened(handle)))),
        code => Err(code),
    }
}

/// RegDeleteKeyW's core: `path` below `key` deleted.
fn delete_key(key: u32, path: &UnicodeString) -> u32 {
    let mut handle = 0u32;
    let code = open_key(key, path, DELETE, &mut handle);
    if code != ERROR_SUCCESS {
        return code;
    }
    let handle = Opened(handle);
    // SAFETY: our own handle.
    error(unsafe { nt::NtDeleteKey(handle.0) })
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
    let mut result = 0u32;
    // SAFETY: the buffer is ours, of its size.
    let status = unsafe {
        nt::NtEnumerateKey(
            key,
            index,
            KEY_BASIC_INFORMATION,
            name.bytes.as_mut_ptr(),
            name.bytes.len() as u32,
            &mut result,
        )
    };
    if status != STATUS_SUCCESS {
        return Err(error(status));
    }
    Ok(name)
}

/// What a value query found: its error (ERROR_SUCCESS, ERROR_MORE_DATA when the data did not
/// fit, another for no value), its type and its data's size in bytes.
struct Found {
    code: u32,
    kind: u32,
    size: u32,
}

/// Query `name`'s value of the NT key `key` into `room` bytes at `data` (none for null): the data
/// is written only when it fits whole.
fn query_value(key: u32, name: &UnicodeString, data: *mut u8, room: u32) -> Found {
    /// KEY_VALUE_PARTIAL_INFORMATION with room for short data.
    #[repr(C, align(8))]
    struct Partial([u8; PARTIAL_DATA + 256]);
    let mut partial = Partial([0; PARTIAL_DATA + 256]);
    let mut result = 0u32;
    // SAFETY: the name lives across the call; the buffer is ours, of its size.
    let status = unsafe {
        nt::NtQueryValueKey(
            key,
            name,
            KEY_VALUE_PARTIAL_INFORMATION,
            partial.0.as_mut_ptr(),
            partial.0.len() as u32,
            &mut result,
        )
    };
    if status != STATUS_SUCCESS && status != STATUS_BUFFER_OVERFLOW {
        return Found {
            code: error(status),
            kind: 0,
            size: 0,
        };
    }
    let word = |at: usize| u32::from_le_bytes(partial.0[at..at + 4].try_into().unwrap());
    let mut found = Found {
        code: ERROR_SUCCESS,
        kind: word(4),
        size: word(8),
    };
    if data.is_null() {
        return found;
    }
    if found.size > room {
        found.code = ERROR_MORE_DATA;
        return found;
    }
    if status == STATUS_SUCCESS {
        // SAFETY: the caller's buffer holds `room` bytes, at least the data's.
        unsafe {
            core::ptr::copy_nonoverlapping(
                partial.0[PARTIAL_DATA..].as_ptr(),
                data,
                found.size as usize,
            )
        };
        return found;
    }
    // Data longer than the buffer above: read again, whole.
    let whole = match Block::new(PARTIAL_DATA + found.size as usize) {
        Ok(whole) => whole,
        Err(code) => {
            found.code = code;
            return found;
        }
    };
    // SAFETY: the name lives across the call; the block is ours, of its size.
    let status = unsafe {
        nt::NtQueryValueKey(
            key,
            name,
            KEY_VALUE_PARTIAL_INFORMATION,
            whole.at,
            PARTIAL_DATA as u32 + found.size,
            &mut result,
        )
    };
    if status != STATUS_SUCCESS {
        // The value changed in between.
        found.code = if status == STATUS_BUFFER_OVERFLOW {
            ERROR_MORE_DATA
        } else {
            error(status)
        };
        return found;
    }
    // SAFETY: the block's data, of the size found; the caller's buffer holds it.
    unsafe {
        core::ptr::copy_nonoverlapping(whole.at.add(PARTIAL_DATA), data, found.size as usize)
    };
    found
}

/// RegQueryValueExW's core over the NT key `key`: the type, the size and, when it fits, the
/// data. A failure leaves the type, and the size when data was given, as they were; with no data
/// the size is zeroed.
fn query_value_w(
    key: u32,
    name: &UnicodeString,
    kind: *mut u32,
    data: *mut u8,
    size: *mut u32,
) -> u32 {
    let room = if data.is_null() {
        0
    } else {
        // SAFETY: the caller's size, given with the data.
        unsafe { *size }
    };
    let found = query_value(key, name, data, room);
    if found.code != ERROR_SUCCESS && found.code != ERROR_MORE_DATA {
        if data.is_null() {
            put(size, 0);
        }
        return found.code;
    }
    put(kind, found.kind);
    put(size, found.size);
    found.code
}

/// RegQueryValueExA's core over the NT key `key`: as the W core, a string value converted to the
/// ANSI code page in the caller's buffer, its sizes the ANSI ones.
fn query_value_a(
    key: u32,
    name: &UnicodeString,
    kind: *mut u32,
    data: *mut u8,
    size: *mut u32,
) -> u32 {
    let room = if data.is_null() {
        0
    } else {
        // SAFETY: the caller's size, given with the data.
        unsafe { *size }
    };
    let found = query_value(key, name, data, room);
    if found.code != ERROR_SUCCESS && found.code != ERROR_MORE_DATA {
        if data.is_null() {
            put(size, 0);
        }
        return found.code;
    }
    if !is_text(found.kind) {
        put(kind, found.kind);
        put(size, found.size);
        return found.code;
    }
    // The Unicode text, in a block of our own: copied from the caller's buffer when it was read
    // there (its conversion overwrites it from the start), read again otherwise.
    let text = match Block::new(found.size as usize) {
        Ok(text) => text,
        Err(code) => return code,
    };
    if found.code == ERROR_SUCCESS && !data.is_null() {
        // SAFETY: the caller's buffer holds the data just read; the block holds as much.
        unsafe { core::ptr::copy_nonoverlapping(data, text.at, found.size as usize) };
    } else {
        let again = query_value(key, name, text.at, found.size);
        if again.code != ERROR_SUCCESS {
            return again.code;
        }
    }
    let mut ansi = 0u32;
    // SAFETY: the block holds the text's bytes.
    unsafe { nt::RtlUnicodeToMultiByteSize(&mut ansi, text.at.cast(), found.size) };
    let code = if data.is_null() {
        ERROR_SUCCESS
    } else if ansi > room {
        ERROR_MORE_DATA
    } else {
        // SAFETY: the caller's buffer holds `room` bytes, at least the ANSI text's.
        unsafe {
            nt::RtlUnicodeToMultiByteN(
                data,
                ansi,
                core::ptr::null_mut(),
                text.at.cast(),
                found.size,
            )
        };
        ERROR_SUCCESS
    };
    put(kind, found.kind);
    put(size, ansi);
    code
}

/// RegSetValueExW's core over the NT key `key`: a string value without its terminator gets one.
fn set_value_w(key: u32, name: &UnicodeString, kind: u32, data: *const u8, size: u32) -> u32 {
    let unterminated = is_text(kind) && size >= 2 && size % 2 == 0 && {
        // SAFETY: the caller's data, `size` bytes of it.
        let last = unsafe { core::ptr::read_unaligned(data.add(size as usize - 2).cast::<u16>()) };
        last != 0
    };
    let terminated;
    let (data, size) = if unterminated {
        terminated = match Block::new(size as usize + 2) {
            Ok(block) => block,
            Err(code) => return code,
        };
        // SAFETY: the block holds the data and a terminator.
        unsafe {
            core::ptr::copy_nonoverlapping(data, terminated.at, size as usize);
            terminated
                .at
                .add(size as usize)
                .cast::<u16>()
                .write_unaligned(0);
        }
        (terminated.at as *const u8, size + 2)
    } else {
        (data, size)
    };
    // SAFETY: the name and the data live across the call.
    error(unsafe { nt::NtSetValueKey(key, name, 0, kind, data, size) })
}

/// RegSetValueExA's core over the NT key `key`: string data converted to Unicode first.
fn set_value_a(key: u32, name: &UnicodeString, kind: u32, data: *const u8, size: u32) -> u32 {
    if !is_text(kind) {
        return set_value_w(key, name, kind, data, size);
    }
    let wide = match Block::new(2 * size as usize) {
        Ok(wide) => wide,
        Err(code) => return code,
    };
    let mut written = 0u32;
    // SAFETY: the caller's data, `size` bytes; the block holds twice as many.
    unsafe { nt::RtlMultiByteToUnicodeN(wide.at.cast(), 2 * size, &mut written, data, size) };
    set_value_w(key, name, kind, wide.at, written)
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
            // SAFETY: the kept handle, no longer kept.
            unsafe { nt::NtClose(kept) };
        }
        return ERROR_SUCCESS;
    }
    // SAFETY: the caller's handle.
    error(unsafe { nt::NtClose(key) })
}

/// RegCreateKeyExW: the key `sub_key` names below `key`, made with every missing key above it,
/// opened when it exists; the handle (NULL on a failure) and, when asked, the disposition.
///
/// # Safety
///
/// The strings are NUL-terminated (the class may be null); the out parameters writable or null.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_RegCreateKeyExW")]
pub unsafe extern "system" fn reg_create_key_ex_w(
    key: u32,
    sub_key: *const u16,
    _reserved: u32,
    class: *const u16,
    options: u32,
    access: u32,
    security: *const u32,
    result: *mut u32,
    disposition: *mut u32,
) -> u32 {
    // SAFETY: the caller's strings.
    let (path, class_name) = unsafe { (counted(sub_key), counted(class)) };
    let class = (!class.is_null()).then_some(&class_name);
    create_key(
        key,
        &path,
        class,
        options,
        access,
        security,
        result,
        disposition,
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
    security: *const u32,
    result: *mut u32,
    disposition: *mut u32,
) -> u32 {
    // SAFETY: the caller's strings.
    let (path, class_name) = match unsafe { (Wide::of(sub_key), Wide::of(class)) } {
        (Ok(path), Ok(class)) => (path, class),
        (Err(code), _) | (_, Err(code)) => return code,
    };
    let class = (!class.is_null()).then_some(&class_name.string);
    create_key(
        key,
        &path.string,
        class,
        options,
        access,
        security,
        result,
        disposition,
    )
}

/// RegOpenKeyExW: the key `sub_key` names below `key` (a new handle to `key`'s own key for none);
/// the handle, NULL on a failure.
///
/// # Safety
///
/// The string is NUL-terminated or null; the result writable.
#[unsafe(export_name = "f2k_export_RegOpenKeyExW")]
pub unsafe extern "system" fn reg_open_key_ex_w(
    key: u32,
    sub_key: *const u16,
    _options: u32,
    access: u32,
    result: *mut u32,
) -> u32 {
    // SAFETY: the caller's string.
    open_key(key, &unsafe { counted(sub_key) }, access, result)
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
    // SAFETY: the caller's string.
    match unsafe { Wide::of(sub_key) } {
        Ok(path) => open_key(key, &path.string, access, result),
        Err(code) => code,
    }
}

/// RegOpenKey's answer for no subkey (a null or empty name): `key` itself, the same handle.
fn open_key_itself(key: u32, result: *mut u32) -> u32 {
    if key == 0 {
        return ERROR_INVALID_HANDLE;
    }
    put(result, key);
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
    // SAFETY: the caller's string.
    let path = unsafe { counted(sub_key) };
    if path.length == 0 {
        return open_key_itself(key, result);
    }
    open_key(key, &path, MAXIMUM_ALLOWED, result)
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
    // SAFETY: the caller's string.
    let path = match unsafe { Wide::of(sub_key) } {
        Ok(path) => path,
        Err(code) => return code,
    };
    if path.string.length == 0 {
        return open_key_itself(key, result);
    }
    open_key(key, &path.string, MAXIMUM_ALLOWED, result)
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
    delete_key(key, &unsafe { counted(sub_key) })
}

/// RegDeleteKeyA: RegDeleteKeyW of the name converted.
///
/// # Safety
///
/// As RegDeleteKeyW's.
#[unsafe(export_name = "f2k_export_RegDeleteKeyA")]
pub unsafe extern "system" fn reg_delete_key_a(key: u32, sub_key: *const u8) -> u32 {
    // SAFETY: the caller's string.
    match unsafe { Wide::of(sub_key) } {
        Ok(path) => delete_key(key, &path.string),
        Err(code) => code,
    }
}

/// RegEnumKeyW: subkey `index`'s name into `name`, `units` long, with its terminator, the subkeys
/// in their names' order; ERROR_MORE_DATA (nothing written) when it does not fit,
/// ERROR_NO_MORE_ITEMS past the last.
///
/// # Safety
///
/// `name` holds `units` units.
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
    // SAFETY: the caller's buffer holds the name and its terminator.
    unsafe {
        core::ptr::copy_nonoverlapping(text.as_ptr(), name, text.len());
        name.add(text.len()).write(0);
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
    let text = counted_units(found.units());
    let mut ansi = AnsiString {
        length: 0,
        maximum_length: bytes.min(0xFFFF) as u16,
        buffer: name,
    };
    // SAFETY: the source is ours; the caller's buffer holds its room.
    error(unsafe { nt::RtlUnicodeStringToAnsiString(&mut ansi, &text, 0) })
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
    // SAFETY: the caller's string.
    query_value_w(key, &unsafe { counted(name) }, kind, data, size)
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
    // SAFETY: the caller's string.
    match unsafe { Wide::of(name) } {
        Ok(name) => query_value_a(key, &name.string, kind, data, size),
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
    // SAFETY: the caller's string.
    set_value_w(key, &unsafe { counted(name) }, kind, data, size)
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
    // SAFETY: the caller's string.
    match unsafe { Wide::of(name) } {
        Ok(name) => set_value_a(key, &name.string, kind, data, size),
        Err(code) => code,
    }
}

/// RegSetValue's core: the default value of `path` below `key` (made with every missing key above
/// it; `key` itself for the empty path) set to the `size` bytes of Unicode text at `text`.
fn set_default(key: u32, path: &UnicodeString, text: *const u8, size: u32) -> u32 {
    let (target, _opened) = if path.length == 0 {
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
            core::ptr::null(),
            &mut handle,
            core::ptr::null_mut(),
        );
        if code != ERROR_SUCCESS {
            return code;
        }
        (handle, Some(Opened(handle)))
    };
    set_value_w(target, &counted_units(&[]), REG_SZ, text, size)
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
    let (path, value) = unsafe { (counted(sub_key), counted(text)) };
    set_default(key, &path, text.cast(), value.length as u32 + 2)
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
    let (path, value) = match unsafe { (Wide::of(sub_key), Wide::of(text)) } {
        (Ok(path), Ok(value)) => (path, value),
        (Err(code), _) | (_, Err(code)) => return code,
    };
    // The converted string's buffer holds its terminator past its length.
    set_default(
        key,
        &path.string,
        value.string.buffer.cast(),
        value.string.length as u32 + 2,
    )
}

/// RegQueryValue's core: the default value of `path` below `key` (`key` itself for the empty
/// path) through `query` (the W or the A form), into `data`, `*size` bytes long. A key with no
/// default value answers the empty string (`unit` bytes, its terminator); one of a type other
/// than REG_SZ is ERROR_INVALID_DATA, its data written all the same.
fn query_default(
    key: u32,
    path: &UnicodeString,
    data: *mut u8,
    size: *mut u32,
    unit: u32,
    query: fn(u32, &UnicodeString, *mut u32, *mut u8, *mut u32) -> u32,
) -> u32 {
    if !data.is_null() && size.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let (target, _opened) = match subkey(key, path, KEY_QUERY_VALUE) {
        Ok(target) => target,
        Err(code) => return code,
    };
    let mut kind = 0u32;
    match query(target, &counted_units(&[]), &mut kind, data, size) {
        ERROR_FILE_NOT_FOUND => {
            if !data.is_null() {
                // SAFETY: the caller's size, given with the data.
                if unsafe { *size } < unit {
                    put(size, unit);
                    return ERROR_MORE_DATA;
                }
                // SAFETY: the caller's buffer holds a terminator.
                unsafe { core::ptr::write_bytes(data, 0, unit as usize) };
            }
            put(size, unit);
            ERROR_SUCCESS
        }
        ERROR_SUCCESS if kind != REG_SZ => ERROR_INVALID_DATA,
        code => code,
    }
}

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
    // SAFETY: the caller's string.
    let path = unsafe { counted(sub_key) };
    query_default(key, &path, data.cast(), size, 2, query_value_w)
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
    // SAFETY: the caller's string.
    match unsafe { Wide::of(sub_key) } {
        Ok(path) => query_default(key, &path.string, data, size, 1, query_value_a),
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
        let wide = unsafe { Wide::of(b"Software\\F2K\0".as_ptr()) }.unwrap();
        // SAFETY: the converted string's units.
        let units = unsafe {
            core::slice::from_raw_parts(wide.string.buffer, wide.string.length as usize / 2)
        };
        assert_eq!(String::from_utf16(units).unwrap(), "Software\\F2K");
        // SAFETY: null is the empty string.
        assert_eq!(
            unsafe { Wide::of(core::ptr::null()) }
                .unwrap()
                .string
                .length,
            0
        );
    }
}
