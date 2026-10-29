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

use rtl::array_vec::ArrayVec;
use rtl::nt::info::{
    KeyBasicInformation,
    KeyFullInformation,
    KeyNodeInformation,
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    VariableSize,
};

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

info_class! {
    /// The key information classes (KEY_INFORMATION_CLASS).
    pub enum KeyClass {
        Basic = 0,
        Node = 1,
        Full = 2,
    }
}

info_class! {
    /// The value information classes (KEY_VALUE_INFORMATION_CLASS).
    pub enum ValueClass {
        Basic = 0,
        Full = 1,
        Partial = 2,
    }
}

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

/// The largest fixed part a reply has (KEY_FULL_INFORMATION's).
const MAX_FIXED: usize = KeyFullInformation::FIXED_SIZE;

/// An information class's answer: its structure's fixed part, then the variable parts (names,
/// class, data) in order, the fixed part's offsets saying where.
pub struct Reply<'a> {
    pub fixed: ArrayVec<u8, MAX_FIXED>,
    pub parts: [&'a [u8]; 2],
}

impl<'a> Reply<'a> {
    /// The answer of `structure` (its fixed part) and the parts that follow it.
    fn new<T: VariableSize>(structure: &T, parts: [&'a [u8]; 2]) -> Self {
        const { assert!(T::FIXED_SIZE <= MAX_FIXED) };
        let mut fixed = ArrayVec::new();
        fixed
            .try_extend_from_slice(structure.fixed_part())
            .expect("no fixed part is larger than the largest");
        Reply { fixed, parts }
    }
}

impl Reply<'_> {
    /// The bytes the whole answer takes.
    pub fn size(&self) -> usize {
        self.fixed.len() + self.parts.iter().map(|part| part.len()).sum::<usize>()
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
        if length < self.fixed.len() {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        let mut at = 0;
        for piece in core::iter::once(self.fixed.as_slice()).chain(self.parts) {
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

/// Key information class `class` of `info`: STATUS_INVALID_PARAMETER for a class Windows 2000
/// does not define.
pub fn key_reply<'a>(class: u32, info: &crate::cm::KeyInfo<'a>) -> Result<Reply<'a>, NtStatus> {
    let class = KeyClass::try_from(class).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let name = unit_bytes(info.name);
    let class_bytes = unit_bytes(info.class);
    Ok(match class {
        // The name.
        KeyClass::Basic => Reply::new(
            &KeyBasicInformation {
                last_write_time: info.last_write,
                name_length: name.len() as u32,
                ..Default::default()
            },
            [name, &[][..]],
        ),
        // The name, then the class.
        KeyClass::Node => Reply::new(
            &KeyNodeInformation {
                last_write_time: info.last_write,
                class_offset: (KeyNodeInformation::FIXED_SIZE + name.len()) as u32,
                class_length: class_bytes.len() as u32,
                name_length: name.len() as u32,
                ..Default::default()
            },
            [name, class_bytes],
        ),
        // The class.
        KeyClass::Full => Reply::new(
            &KeyFullInformation {
                last_write_time: info.last_write,
                class_offset: KeyFullInformation::FIXED_SIZE as u32,
                class_length: class_bytes.len() as u32,
                sub_keys: info.subkeys,
                max_name_len: info.max_subkey_name,
                max_class_len: info.max_subkey_class,
                values: info.values,
                max_value_name_len: info.max_value_name,
                max_value_data_len: info.max_value_data,
                ..Default::default()
            },
            [class_bytes, &[][..]],
        ),
    })
}

/// Value information class `class` of `value`: STATUS_INVALID_PARAMETER for a class Windows 2000
/// does not define.
pub fn value_reply<'a>(
    class: u32,
    value: &crate::cm::ValueInfo<'a>,
) -> Result<Reply<'a>, NtStatus> {
    let class = ValueClass::try_from(class).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let name = unit_bytes(value.name);
    let data = value.data;
    Ok(match class {
        // The name.
        ValueClass::Basic => Reply::new(
            &KeyValueBasicInformation {
                kind: value.kind,
                name_length: name.len() as u32,
                ..Default::default()
            },
            [name, &[][..]],
        ),
        // The name, then the data.
        ValueClass::Full => Reply::new(
            &KeyValueFullInformation {
                kind: value.kind,
                data_offset: (KeyValueFullInformation::FIXED_SIZE + name.len()) as u32,
                data_length: data.len() as u32,
                name_length: name.len() as u32,
                ..Default::default()
            },
            [name, data],
        ),
        // The data.
        ValueClass::Partial => Reply::new(
            &KeyValuePartialInformation {
                kind: value.kind,
                data_length: data.len() as u32,
                ..Default::default()
            },
            [data, &[][..]],
        ),
    })
}

#[cfg(target_arch = "x86")]
pub use services::*;

/// The services themselves, on the calling process's handles and the kernel's registry.
#[cfg(target_arch = "x86")]
mod services {
    use super::super::attributes::{self, Name};
    use super::super::call::{calling_process, Handle, NtCall, NtResult, UserAddr, UserPtr};
    use super::*;
    use crate::cm::{with_registry, Key, KeyBody, Registry, Scratch, MAX_VALUE_NAME, SEPARATOR};
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
            .lookup_handle(handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let id = entry.object_id().ok_or(STATUS_INVALID_HANDLE)?;
        if id.kind != ObjectType::Key {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        if entry.access & needed != needed {
            return Err(STATUS_ACCESS_DENIED);
        }
        ob::locked(|directory| directory.key(id).and_then(|body| body.key))
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

    /// What an OBJECT_ATTRIBUTES names: the key a path starts from, the path below it, and
    /// whether the handle is inherited.
    struct KeyPath<'n> {
        root: Key,
        path: &'n [u16],
        inherit: bool,
    }

    /// Read the OBJECT_ATTRIBUTES at `attributes`, their name into `name` (see [`KeyPath`]).
    fn resolve(attributes: UserAddr, name: &mut Name) -> Result<KeyPath<'_>, NtStatus> {
        if attributes.is_null() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let read = attributes::read(attributes, name)?;
        let (name, inherit) = (read.units(), read.inherit());
        if read.root != 0 {
            let root = key_of(read.root, 0)?;
            if name.first() == Some(&SEPARATOR) {
                return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
            }
            return Ok(KeyPath {
                root,
                path: name,
                inherit,
            });
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
        Ok(KeyPath {
            root: with_registry(|registry| registry.root()),
            path: &name[start..],
            inherit,
        })
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

    /// `bytes` bytes of the caller's memory at `at`, copied into a scratch block of the registry's
    /// arena. The copy runs outside the registry: a fault in it may wait, and another thread's
    /// service reach the registry meanwhile.
    fn capture(at: UserAddr, bytes: usize) -> Result<Scratch, NtStatus> {
        let mut scratch = with_registry(|registry| registry.scratch(bytes))?;
        match at.read(scratch.bytes_mut()) {
            Ok(()) => Ok(scratch),
            Err(fault) => {
                with_registry(|registry| registry.release(scratch));
                Err(fault.into())
            }
        }
    }

    /// The counted string at `at` captured (see [`capture`]): a value name, or a class. None (a
    /// null pointer) is the empty name.
    fn capture_counted(at: UserAddr) -> Result<Scratch, NtStatus> {
        let (units, buffer) = if at.is_null() {
            (0, UserAddr(0))
        } else {
            counted(at)?
        };
        capture(buffer, 2 * units)
    }

    /// Run `step` on the registry with the counted string at `at` captured (see
    /// [`capture_counted`]), its block given back after.
    fn with_counted<R>(
        at: UserAddr,
        step: impl FnOnce(&mut Registry, &[u16]) -> Result<R, NtStatus>,
    ) -> Result<R, NtStatus> {
        let name = capture_counted(at)?;
        with_registry(|registry| {
            let result = step(registry, name.units());
            registry.release(name);
            result
        })
    }

    /// A new key object for `key`, its handle (with `desired`'s rights) into `slot`; a slot that
    /// faults takes the handle back (STATUS_ACCESS_VIOLATION).
    fn publish(slot: UserPtr<u32>, key: Key, desired: u32, inherit: bool) -> Result<u32, NtStatus> {
        let id = ob::locked(|directory| directory.create_key(KeyBody::of(key)))
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let process = calling_process();
        let handle = ob::publish(process, id, granted(desired), inherit)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?
            .get();
        if slot.write(handle).is_err() {
            process.close_handle(handle);
            return Err(STATUS_ACCESS_VIOLATION);
        }
        Ok(handle)
    }

    /// An answer staged for the caller's buffer: what the buffer takes of it, copied out of the
    /// registry; the size the whole takes; the status its delivery answers.
    struct Staged {
        bytes: Scratch,
        size: usize,
        status: NtResult,
    }

    /// The answer `reply` makes of the registry, staged for a buffer of `length` bytes inside the
    /// registry's step (see [`Reply::deliver`]); [`answer`] writes it to the caller once the step
    /// is over. `reply` runs twice, once to size the block and once to fill it, on a registry
    /// that has not changed between.
    fn stage(
        registry: &mut Registry,
        length: u32,
        reply: impl Fn(&Registry) -> Result<Reply<'_>, NtStatus>,
    ) -> Result<Staged, NtStatus> {
        let (size, fixed_size) = reply(registry).map(|made| (made.size(), made.fixed.len()))?;
        let room = if (length as usize) < fixed_size {
            0
        } else {
            size.min(length as usize)
        };
        let mut bytes = registry.scratch(room)?;
        let made = match reply(registry) {
            Ok(made) => made,
            Err(status) => {
                registry.release(bytes);
                return Err(status);
            }
        };
        let status = made.deliver(length, |at, piece| {
            bytes.bytes_mut()[at..at + piece.len()].copy_from_slice(piece);
            Ok(())
        });
        Ok(Staged {
            bytes,
            size,
            status,
        })
    }

    /// The staged answer to the caller: its size into ResultLength, then what the buffer takes of
    /// it into the buffer; its block goes back either way.
    fn answer(staged: Staged, out: UserAddr, result: UserPtr<u32>) -> NtResult {
        let Staged {
            bytes,
            size,
            status,
        } = staged;
        let written = result.write(size as u32).and_then(|()| {
            if bytes.bytes().is_empty() {
                Ok(())
            } else {
                out.write(bytes.bytes())
            }
        });
        with_registry(|registry| registry.release(bytes));
        written?;
        status
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
        let mut name = Name::new();
        let KeyPath {
            root,
            path,
            inherit,
        } = resolve(attributes, &mut name)?;
        if calling_process().handles_full() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let now = now();
        let (key, created) = with_counted(class, |registry, class| {
            registry.create(root, path, class, now)
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
        let mut name = Name::new();
        let path = resolve(attributes, &mut name)?;
        let key = with_registry(|registry| registry.open(path.root, path.path))?;
        publish(slot, key, desired, path.inherit)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtDeleteKey: the key goes, with its values; its handles stay open, answering
    /// STATUS_KEY_DELETED. STATUS_CANNOT_DELETE for a key with subkeys or a hive's root.
    pub fn delete_key(_: &mut NtCall, handle: Handle) -> NtResult {
        let key = key_of(handle.raw(), DELETE)?;
        let now = now();
        with_registry(|registry| registry.delete(key, now))?;
        Ok(STATUS_SUCCESS)
    }

    /// NtFlushKey: nothing to write (the registry lives in memory), so a live key is done.
    pub fn flush_key(_: &mut NtCall, handle: Handle) -> NtResult {
        let key = key_of(handle.raw(), 0)?;
        with_registry(|registry| registry.check(key))?;
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
        let staged = with_registry(|registry| {
            stage(registry, length, |registry| {
                key_reply(class, &registry.info(key)?)
            })
        })?;
        answer(staged, out, result)
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
        let staged = with_registry(|registry| {
            let subkey = registry.subkey(key, index)?.ok_or(STATUS_NO_MORE_ENTRIES)?;
            stage(registry, length, |registry| {
                key_reply(class, &registry.info(subkey)?)
            })
        })?;
        answer(staged, out, result)
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
        let staged = with_counted(name, |registry, name| {
            stage(registry, length, |registry| {
                value_reply(class, &registry.query_value(key, name)?)
            })
        })?;
        answer(staged, out, result)
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
        let staged = with_registry(|registry| {
            stage(registry, length, |registry| {
                let value = registry
                    .value_at(key, index)?
                    .ok_or(STATUS_NO_MORE_ENTRIES)?;
                value_reply(class, &value)
            })
        })?;
        answer(staged, out, result)
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
        let now = now();
        let name = capture_counted(name)?;
        // The key's state answers before the data's copy, as when the copy ran inside the registry.
        let data = with_registry(|registry| registry.check(key))
            .and_then(|_| capture(data, size as usize));
        with_registry(|registry| {
            let set = data.and_then(|data| registry.set_value(key, name.units(), kind, data, now));
            registry.release(name);
            set
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
        let now = now();
        with_counted(name, |registry, name| registry.delete_value(key, name, now))?;
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
        let reply = key_reply(KeyClass::Basic as u32, &info).unwrap();
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
        let partial = value_reply(ValueClass::Partial as u32, &value).unwrap();
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
        let full = value_reply(ValueClass::Full as u32, &value).unwrap();
        let (out, _) = delivered(&full, 28);
        assert_eq!(
            &out[8..12],
            &24u32.to_le_bytes(),
            "DataOffset past the name"
        );
        assert_eq!(&out[20..24], unit_bytes(&name));
        assert_eq!(&out[24..28], b"a\0\0\0");
        let basic = value_reply(ValueClass::Basic as u32, &value).unwrap();
        assert_eq!(basic.size(), 16);
    }
}
