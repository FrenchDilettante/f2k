//! The key services: NtCreateKey and NtOpenKey, NtDeleteKey and NtFlushKey, NtQueryKey and
//! NtEnumerateKey, NtQueryValueKey, NtEnumerateValueKey, NtSetValueKey and NtDeleteValueKey, over
//! the configuration manager's registry (`cm`). advapi32's Reg* calls are Win32 code over these,
//! as on Windows 2000.
//!
//! A key is named by an absolute path under `\Registry`, or by a path relative to a key handle
//! (the OBJECT_ATTRIBUTES' RootDirectory); either way case-insensitively, one trailing separator
//! ignored. A relative path starting with a separator, or an absolute one not starting with one,
//! is STATUS_OBJECT_PATH_SYNTAX_BAD; a missing key on the way STATUS_OBJECT_NAME_NOT_FOUND.
//! NtCreateKey makes the path's last key alone: the ones above it must exist. Each open is a key
//! object holding the rights its open was granted (the generic ones mapped to the key rights; with
//! no security descriptors, every right asked for is granted), and each service checks the right
//! it needs, as the object manager does, before it acts: KEY_QUERY_VALUE to query a key or a
//! value, KEY_SET_VALUE to set or delete a value, KEY_ENUMERATE_SUB_KEYS to list subkeys, DELETE
//! to delete the key; a key handle as a root needs none. A key deleted through another handle
//! answers STATUS_KEY_DELETED to every service through its own.
//!
//! The information classes are Windows 2000's documented structures: KEY_BASIC_INFORMATION,
//! KEY_NODE_INFORMATION and KEY_FULL_INFORMATION for a key, KEY_VALUE_BASIC_INFORMATION,
//! KEY_VALUE_FULL_INFORMATION and KEY_VALUE_PARTIAL_INFORMATION for a value; another class is
//! STATUS_INVALID_PARAMETER. A buffer too small for the structure's fixed part is
//! STATUS_BUFFER_TOO_SMALL, nothing written; one holding the fixed part but not the whole is
//! STATUS_BUFFER_OVERFLOW, what fits written; the size the whole takes goes to ResultLength either
//! way.

use crate::cm::unit_bytes;
use crate::status::*;

/// The key rights.
pub const KEY_QUERY_VALUE: u32 = 0x0001;
pub const KEY_SET_VALUE: u32 = 0x0002;
pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
pub const DELETE: u32 = 0x0001_0000;
/// The generic rights' mapping for keys, and what MAXIMUM_ALLOWED grants (every key right).
pub const KEY_READ: u32 = 0x0002_0019;
pub const KEY_WRITE: u32 = 0x0002_0006;
pub const KEY_EXECUTE: u32 = 0x0002_0019;
pub const KEY_ALL_ACCESS: u32 = 0x000F_003F;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// The standard and the key-specific rights: what a request names besides the generic ones.
const SPECIFIC_AND_STANDARD: u32 = 0x00FF_FFFF;

/// NtCreateKey's dispositions.
pub const REG_CREATED_NEW_KEY: u32 = 1;
pub const REG_OPENED_EXISTING_KEY: u32 = 2;

/// The key information classes.
const KEY_BASIC_INFORMATION: u32 = 0;
const KEY_NODE_INFORMATION: u32 = 1;
const KEY_FULL_INFORMATION: u32 = 2;
/// The value information classes.
const KEY_VALUE_BASIC_INFORMATION: u32 = 0;
const KEY_VALUE_FULL_INFORMATION: u32 = 1;
const KEY_VALUE_PARTIAL_INFORMATION: u32 = 2;

/// The rights an open asking for `desired` is granted: the rights it names, the generic ones
/// mapped to the key rights, MAXIMUM_ALLOWED as every key right.
pub fn granted(desired: u32) -> u32 {
    let mut access = desired & SPECIFIC_AND_STANDARD;
    for (generic, rights) in [
        (GENERIC_READ, KEY_READ),
        (GENERIC_WRITE, KEY_WRITE),
        (GENERIC_EXECUTE, KEY_EXECUTE),
        (GENERIC_ALL | MAXIMUM_ALLOWED, KEY_ALL_ACCESS),
    ] {
        if desired & generic != 0 {
            access |= rights;
        }
    }
    access
}

/// An information class's answer: its structure's fixed part, then the variable parts (names,
/// class, data) in order, the fixed part's offsets saying where.
pub struct Reply<'a> {
    pub fixed: [u8; 44],
    pub fixed_size: usize,
    pub parts: [&'a [u8]; 2],
}

impl Reply<'_> {
    /// The bytes the whole answer takes.
    pub fn size(&self) -> usize {
        self.fixed_size + self.parts.iter().map(|part| part.len()).sum::<usize>()
    }

    /// Hand what a buffer of `length` bytes takes of the answer to `write` (its offset, its bytes):
    /// nothing below the fixed part (STATUS_BUFFER_TOO_SMALL), what fits when not the whole
    /// (STATUS_BUFFER_OVERFLOW), else the whole (STATUS_SUCCESS). A failed write is the status
    /// `write` answers.
    pub fn deliver(
        &self,
        length: u32,
        mut write: impl FnMut(usize, &[u8]) -> Result<(), NtStatus>,
    ) -> Result<NtStatus, NtStatus> {
        let length = length as usize;
        if length < self.fixed_size {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        let mut at = 0;
        for piece in core::iter::once(&self.fixed[..self.fixed_size]).chain(self.parts) {
            let room = length.saturating_sub(at).min(piece.len());
            if room > 0 {
                write(at, &piece[..room])?;
            }
            at += piece.len();
        }
        if self.size() > length {
            Err(STATUS_BUFFER_OVERFLOW)
        } else {
            Ok(STATUS_SUCCESS)
        }
    }
}

/// A fixed part of dwords (the rest of the 44 bytes zero), `size` bytes of it.
fn fixed(words: &[u32], size: usize) -> ([u8; 44], usize) {
    (super::system::layout::<44>(words), size)
}

/// Key information class `class` of `info`: STATUS_INVALID_PARAMETER for a class Windows 2000
/// does not define.
pub fn key_reply<'a>(class: u32, info: &crate::cm::KeyInfo<'a>) -> Result<Reply<'a>, NtStatus> {
    let name = unit_bytes(info.name);
    let class_bytes = unit_bytes(info.class);
    let time = [info.last_write as u32, (info.last_write >> 32) as u32];
    let ((fixed, fixed_size), parts) = match class {
        // LastWriteTime, TitleIndex, NameLength; Name.
        KEY_BASIC_INFORMATION => (
            fixed(&[time[0], time[1], 0, name.len() as u32], 16),
            [name, &[][..]],
        ),
        // LastWriteTime, TitleIndex, ClassOffset, ClassLength, NameLength; Name, then Class.
        KEY_NODE_INFORMATION => (
            fixed(
                &[
                    time[0],
                    time[1],
                    0,
                    24 + name.len() as u32,
                    class_bytes.len() as u32,
                    name.len() as u32,
                ],
                24,
            ),
            [name, class_bytes],
        ),
        // LastWriteTime, TitleIndex, ClassOffset, ClassLength, SubKeys, MaxNameLen, MaxClassLen,
        // Values, MaxValueNameLen, MaxValueDataLen; Class.
        KEY_FULL_INFORMATION => (
            fixed(
                &[
                    time[0],
                    time[1],
                    0,
                    44,
                    class_bytes.len() as u32,
                    info.subkeys,
                    info.max_subkey_name,
                    info.max_subkey_class,
                    info.values,
                    info.max_value_name,
                    info.max_value_data,
                ],
                44,
            ),
            [class_bytes, &[][..]],
        ),
        _ => return Err(STATUS_INVALID_PARAMETER),
    };
    Ok(Reply {
        fixed,
        fixed_size,
        parts,
    })
}

/// Value information class `class` of `value`: STATUS_INVALID_PARAMETER for a class Windows 2000
/// does not define.
pub fn value_reply<'a>(
    class: u32,
    value: &crate::cm::ValueInfo<'a>,
) -> Result<Reply<'a>, NtStatus> {
    let name = unit_bytes(value.name);
    let data = value.data;
    let ((fixed, fixed_size), parts) = match class {
        // TitleIndex, Type, NameLength; Name.
        KEY_VALUE_BASIC_INFORMATION => (
            fixed(&[0, value.kind, name.len() as u32], 12),
            [name, &[][..]],
        ),
        // TitleIndex, Type, DataOffset, DataLength, NameLength; Name, then the data.
        KEY_VALUE_FULL_INFORMATION => (
            fixed(
                &[
                    0,
                    value.kind,
                    20 + name.len() as u32,
                    data.len() as u32,
                    name.len() as u32,
                ],
                20,
            ),
            [name, data],
        ),
        // TitleIndex, Type, DataLength; the data.
        KEY_VALUE_PARTIAL_INFORMATION => (
            fixed(&[0, value.kind, data.len() as u32], 12),
            [data, &[][..]],
        ),
        _ => return Err(STATUS_INVALID_PARAMETER),
    };
    Ok(Reply {
        fixed,
        fixed_size,
        parts,
    })
}

#[cfg(target_arch = "x86")]
pub use services::*;

/// The services themselves, on the calling process's handles and the kernel's registry.
#[cfg(target_arch = "x86")]
mod services {
    use super::super::attributes::{self, MAX_NAME};
    use super::super::call::{calling_process, Handle, NtCall, NtResult, UserAddr, UserPtr};
    use super::*;
    use crate::cm::{self, Key, KeyBody, MAX_VALUE_NAME, SEPARATOR};
    use crate::nt::object::is_console_handle;
    use crate::ob::{self, ObjectType};

    /// The registry's root in the object namespace.
    const REGISTRY: &str = "\\Registry";

    /// Now, as the keys' last-write times keep it.
    fn now() -> u64 {
        crate::time::system_filetime()
    }

    /// The key `handle` names in the calling process, its open granted `needed`:
    /// STATUS_INVALID_HANDLE for a handle naming nothing (a console handle included),
    /// STATUS_OBJECT_TYPE_MISMATCH for another kind of object, STATUS_ACCESS_DENIED for an open
    /// without the rights. The key itself may be gone (the registry's answers say so).
    fn key_of(handle: u32, needed: u32) -> Result<Key, NtStatus> {
        if is_console_handle(handle) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let entry = calling_process()
            .handles()
            .lookup(handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let id = entry.object_id().ok_or(STATUS_INVALID_HANDLE)?;
        if id.kind != ObjectType::Key {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        if entry.access & needed != needed {
            return Err(STATUS_ACCESS_DENIED);
        }
        ob::directory()
            .key(id)
            .map(|body| body.key)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Whether `units` begin with `prefix` (ASCII, case-insensitively).
    fn starts_with(units: &[u16], prefix: &str) -> bool {
        units.len() >= prefix.len()
            && units
                .iter()
                .zip(prefix.bytes())
                .all(|(&unit, byte)| unit < 0x80 && (unit as u8).eq_ignore_ascii_case(&byte))
    }

    /// What an OBJECT_ATTRIBUTES names: the key a path starts from, the path below it (its units'
    /// range in `units`), and whether the handle is inherited.
    fn resolve(
        attributes: UserAddr,
        units: &mut [u16; MAX_NAME],
    ) -> Result<(Key, core::ops::Range<usize>, bool), NtStatus> {
        if attributes.is_null() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let read = attributes::read(attributes, units)?;
        let length = read.length.unwrap_or(0);
        let name = &units[..length];
        if read.root != 0 {
            let root = key_of(read.root, 0)?;
            if name.first() == Some(&SEPARATOR) {
                return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
            }
            return Ok((root, 0..length, read.inherit()));
        }
        if name.is_empty() {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if name[0] != SEPARATOR {
            return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        if !starts_with(name, REGISTRY) {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let start = match &name[REGISTRY.len()..] {
            [] => REGISTRY.len(),
            [separator, ..] if *separator == SEPARATOR => REGISTRY.len() + 1,
            _ => return Err(STATUS_OBJECT_NAME_NOT_FOUND),
        };
        Ok((cm::registry().root(), start..length, read.inherit()))
    }

    /// A counted string at `at` (a UNICODE_STRING): its length in units and its buffer.
    /// STATUS_INVALID_PARAMETER past a value name's longest.
    fn counted(at: UserAddr) -> Result<(usize, UserAddr), NtStatus> {
        let string = at.cast::<rtl::nt::UnicodeString<u32>>().read()?;
        let units = usize::from(string.length) / 2;
        if units > MAX_VALUE_NAME {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok((units, UserAddr(string.buffer)))
    }

    /// Run `then` on the registry with the counted string at `at` read: a value name, or a class.
    /// None (a null pointer) is the empty name.
    fn with_counted<R>(
        at: UserAddr,
        then: impl FnOnce(&mut cm::Registry, &[u16]) -> Result<R, NtStatus>,
    ) -> Result<R, NtStatus> {
        let (units, buffer) = if at.is_null() {
            (0, UserAddr(0))
        } else {
            counted(at)?
        };
        cm::registry().with_scratch(
            units,
            |bytes| buffer.read(bytes).map_err(NtStatus::from),
            then,
        )?
    }

    /// A new key object for `key`, its handle (with `desired`'s rights) into `slot`; a slot that
    /// faults takes the handle back (STATUS_ACCESS_VIOLATION).
    fn publish(slot: UserPtr<u32>, key: Key, desired: u32, inherit: bool) -> Result<u32, NtStatus> {
        let id = ob::directory()
            .create_key(KeyBody { key })
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let process = calling_process();
        let handle = ob::publish(process, id, granted(desired), inherit, None)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        if slot.write(handle).is_err() {
            process.close_handle(handle);
            return Err(STATUS_ACCESS_VIOLATION);
        }
        Ok(handle)
    }

    /// The answer into the caller's buffer, its size into ResultLength.
    fn answer(reply: &Reply, out: UserAddr, length: u32, result: UserPtr<u32>) -> NtResult {
        result.write(reply.size() as u32)?;
        reply.deliver(length, |at, bytes| {
            out.offset(at as u32).write(bytes).map_err(NtStatus::from)
        })
    }

    /// NtCreateKey: the key the attributes name, made when missing (with the class), opened
    /// otherwise; its handle into KeyHandle and what happened into Disposition (when given). The
    /// title index and the options are not consulted (the registry is never saved, so a key is
    /// as volatile as any).
    #[allow(clippy::too_many_arguments)]
    pub fn create_key(
        _: &mut NtCall,
        slot: UserPtr<u32>,
        desired: u32,
        attributes: UserAddr,
        _title_index: u32,
        class: UserAddr,
        _options: u32,
        disposition: UserPtr<u32>,
    ) -> NtResult {
        let mut units = [0u16; MAX_NAME];
        let (root, path, inherit) = resolve(attributes, &mut units)?;
        if calling_process().handles().is_full() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let path = &units[path];
        let (key, created) = with_counted(class, |registry, class| {
            registry.create(root, path, class, now())
        })?;
        let handle = publish(slot, key, desired, inherit)?;
        let outcome = if created {
            REG_CREATED_NEW_KEY
        } else {
            REG_OPENED_EXISTING_KEY
        };
        if disposition.write_optional(outcome).is_err() {
            calling_process().close_handle(handle);
            return Err(STATUS_ACCESS_VIOLATION);
        }
        Ok(STATUS_SUCCESS)
    }

    /// NtOpenKey: the key the attributes name, its handle into KeyHandle.
    pub fn open_key(
        _: &mut NtCall,
        slot: UserPtr<u32>,
        desired: u32,
        attributes: UserAddr,
    ) -> NtResult {
        let mut units = [0u16; MAX_NAME];
        let (root, path, inherit) = resolve(attributes, &mut units)?;
        let key = cm::registry().open(root, &units[path])?;
        publish(slot, key, desired, inherit)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtDeleteKey: the key goes, with its values; its handles stay open, answering
    /// STATUS_KEY_DELETED. STATUS_CANNOT_DELETE for a key with subkeys or a hive's root.
    pub fn delete_key(_: &mut NtCall, handle: Handle) -> NtResult {
        let key = key_of(handle.raw(), DELETE)?;
        cm::registry().delete(key, now())?;
        Ok(STATUS_SUCCESS)
    }

    /// NtFlushKey: nothing to write (the registry lives in memory), so a live key is done.
    pub fn flush_key(_: &mut NtCall, handle: Handle) -> NtResult {
        let key = key_of(handle.raw(), 0)?;
        cm::registry().check(key)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtQueryKey: the key's information of the class asked for.
    pub fn query_key(
        _: &mut NtCall,
        handle: Handle,
        class: u32,
        out: UserAddr,
        length: u32,
        result: UserPtr<u32>,
    ) -> NtResult {
        let key = key_of(handle.raw(), KEY_QUERY_VALUE)?;
        let info = cm::registry().info(key)?;
        answer(&key_reply(class, &info)?, out, length, result)
    }

    /// NtEnumerateKey: subkey `index`'s information of the class asked for, the subkeys in their
    /// names' order; STATUS_NO_MORE_ENTRIES past the last.
    pub fn enumerate_key(
        _: &mut NtCall,
        handle: Handle,
        index: u32,
        class: u32,
        out: UserAddr,
        length: u32,
        result: UserPtr<u32>,
    ) -> NtResult {
        let key = key_of(handle.raw(), KEY_ENUMERATE_SUB_KEYS)?;
        let registry = cm::registry();
        let subkey = registry.subkey(key, index)?.ok_or(STATUS_NO_MORE_ENTRIES)?;
        let info = registry.info(subkey)?;
        answer(&key_reply(class, &info)?, out, length, result)
    }

    /// NtQueryValueKey: the named value's information of the class asked for (the empty name: the
    /// key's default value); STATUS_OBJECT_NAME_NOT_FOUND when the key has none of the name.
    pub fn query_value_key(
        _: &mut NtCall,
        handle: Handle,
        name: UserAddr,
        class: u32,
        out: UserAddr,
        length: u32,
        result: UserPtr<u32>,
    ) -> NtResult {
        let key = key_of(handle.raw(), KEY_QUERY_VALUE)?;
        if name.is_null() {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        with_counted(name, |registry, name| {
            let value = registry.query_value(key, name)?;
            answer(&value_reply(class, &value)?, out, length, result)
        })
    }

    /// NtEnumerateValueKey: value `index`'s information of the class asked for, the values in the
    /// order they were first set; STATUS_NO_MORE_ENTRIES past the last.
    pub fn enumerate_value_key(
        _: &mut NtCall,
        handle: Handle,
        index: u32,
        class: u32,
        out: UserAddr,
        length: u32,
        result: UserPtr<u32>,
    ) -> NtResult {
        let key = key_of(handle.raw(), KEY_QUERY_VALUE)?;
        let value = cm::registry()
            .value_at(key, index)?
            .ok_or(STATUS_NO_MORE_ENTRIES)?;
        answer(&value_reply(class, &value)?, out, length, result)
    }

    /// NtSetValueKey: the named value set to the data, of the type given (the data as given: a
    /// string's terminator is the caller's to count). The title index is not consulted.
    pub fn set_value_key(
        _: &mut NtCall,
        handle: Handle,
        name: UserAddr,
        _title_index: u32,
        kind: u32,
        data: UserAddr,
        size: u32,
    ) -> NtResult {
        let key = key_of(handle.raw(), KEY_SET_VALUE)?;
        if name.is_null() {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        with_counted(name, |registry, name| {
            registry.set_value(key, name, kind, size as usize, now(), |bytes| {
                data.read(bytes).map_err(NtStatus::from)
            })
        })?;
        Ok(STATUS_SUCCESS)
    }

    /// NtDeleteValueKey: the named value goes; STATUS_OBJECT_NAME_NOT_FOUND when the key has none
    /// of the name.
    pub fn delete_value_key(_: &mut NtCall, handle: Handle, name: UserAddr) -> NtResult {
        let key = key_of(handle.raw(), KEY_SET_VALUE)?;
        if name.is_null() {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        with_counted(name, |registry, name| {
            registry.delete_value(key, name, now())
        })?;
        Ok(STATUS_SUCCESS)
    }
}

/// The host builds' key services (see `nt::unserved`): they run on the target's handles and
/// registry; the host tests exercise the pure parts above and the registry itself (`cm`).
#[cfg(not(target_arch = "x86"))]
mod services {
    use super::super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

    unserved! {
        create_key(UserPtr<u32>, u32, UserAddr, u32, UserAddr, u32, UserPtr<u32>);
        open_key(UserPtr<u32>, u32, UserAddr);
        delete_key(Handle);
        flush_key(Handle);
        query_key(Handle, u32, UserAddr, u32, UserPtr<u32>);
        enumerate_key(Handle, u32, u32, UserAddr, u32, UserPtr<u32>);
        query_value_key(Handle, UserAddr, u32, UserAddr, u32, UserPtr<u32>);
        enumerate_value_key(Handle, u32, u32, UserAddr, u32, UserPtr<u32>);
        set_value_key(Handle, UserAddr, u32, u32, UserAddr, u32);
        delete_value_key(Handle, UserAddr);
    }
}

#[cfg(not(target_arch = "x86"))]
pub use services::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generic_rights_map_to_the_key_rights() {
        assert_eq!(granted(KEY_READ), KEY_READ);
        assert_eq!(granted(GENERIC_READ), KEY_READ);
        assert_eq!(granted(GENERIC_WRITE | DELETE), KEY_WRITE | DELETE);
        assert_eq!(granted(MAXIMUM_ALLOWED), KEY_ALL_ACCESS);
        assert_eq!(granted(GENERIC_ALL), KEY_ALL_ACCESS);
        assert_eq!(granted(KEY_READ) & KEY_SET_VALUE, 0);
    }

    /// What a buffer of `length` bytes receives of the reply, and the status.
    fn delivered(reply: &Reply, length: u32) -> (Vec<u8>, Result<NtStatus, NtStatus>) {
        let mut out = vec![0xCCu8; length as usize];
        let status = reply.deliver(length, |at, bytes| {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            Ok(())
        });
        (out, status)
    }

    #[test]
    fn a_reply_fits_overflows_or_is_refused() {
        let name: Vec<u16> = "Alpha".encode_utf16().collect();
        let info = crate::cm::KeyInfo {
            last_write: 0x0102_0304_0506_0708,
            name: &name,
            class: &[],
            subkeys: 0,
            max_subkey_name: 0,
            max_subkey_class: 0,
            values: 0,
            max_value_name: 0,
            max_value_data: 0,
        };
        let reply = key_reply(KEY_BASIC_INFORMATION, &info).unwrap();
        assert_eq!(reply.size(), 26);
        let (out, status) = delivered(&reply, 26);
        assert_eq!(status, Ok(STATUS_SUCCESS));
        assert_eq!(&out[..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&out[12..16], &10u32.to_le_bytes(), "NameLength in bytes");
        assert_eq!(&out[16..], unit_bytes(&name));
        let (out, status) = delivered(&reply, 19);
        assert_eq!(status, Err(STATUS_BUFFER_OVERFLOW));
        assert_eq!(&out[16..19], &unit_bytes(&name)[..3], "what fits");
        assert_eq!(delivered(&reply, 15).1, Err(STATUS_BUFFER_TOO_SMALL));
        assert!(
            delivered(&reply, 15).0.iter().all(|&b| b == 0xCC),
            "nothing written"
        );
        assert_eq!(key_reply(3, &info).err(), Some(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn the_value_classes_lay_out_as_documented() {
        let name: Vec<u16> = "sz".encode_utf16().collect();
        let value = crate::cm::ValueInfo {
            kind: 1,
            name: &name,
            data: b"a\0\0\0",
        };
        let partial = value_reply(KEY_VALUE_PARTIAL_INFORMATION, &value).unwrap();
        let (out, status) = delivered(&partial, 16);
        assert_eq!(status, Ok(STATUS_SUCCESS));
        assert_eq!(out, [0, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, b'a', 0, 0, 0]);
        let (out, status) = delivered(&partial, 12);
        assert_eq!(
            status,
            Err(STATUS_BUFFER_OVERFLOW),
            "the fixed part tells the size"
        );
        assert_eq!(&out[8..12], &4u32.to_le_bytes());
        let full = value_reply(KEY_VALUE_FULL_INFORMATION, &value).unwrap();
        let (out, _) = delivered(&full, 28);
        assert_eq!(
            &out[8..12],
            &24u32.to_le_bytes(),
            "DataOffset past the name"
        );
        assert_eq!(&out[20..24], unit_bytes(&name));
        assert_eq!(&out[24..28], b"a\0\0\0");
        let basic = value_reply(KEY_VALUE_BASIC_INFORMATION, &value).unwrap();
        assert_eq!(basic.size(), 16);
    }
}
