//! OBJECT_ATTRIBUTES: what every service that names an object reads — the root directory handle,
//! the name (a UNICODE_STRING) and the attributes — and the named objects' part of the namespace,
//! `\BaseNamedObjects`, where kernel32 names its events, mutexes, semaphores and sections (and, as
//! they come, its timers).
//!
//! A name is absolute (`\BaseNamedObjects\<name>`, no root), or relative to a root directory
//! handle naming `\BaseNamedObjects`: the directory object kernel32 opens once
//! (BaseGetNamedObjectDirectory, NtOpenDirectoryObject) and names everything relative to, as on
//! Windows 2000 ([`root_of`]).

use super::call::UserAddr;
use crate::status::*;

/// OBJECT_ATTRIBUTES' size, and its Attributes' OBJ_INHERIT and OBJ_OPENIF.
const OBJECT_ATTRIBUTES_SIZE: u32 = 24;
pub const OBJ_INHERIT: u32 = 0x2;
pub const OBJ_OPENIF: u32 = 0x80;

/// The longest name read, in units.
pub const MAX_NAME: usize = 1024;

/// An OBJECT_ATTRIBUTES, read: the root directory handle, the name's length in units (the units
/// themselves in the caller's buffer; none for a null ObjectName) and the attributes.
pub struct Attributes {
    pub root: u32,
    pub length: Option<usize>,
    pub attributes: u32,
}

impl Attributes {
    /// Whether a handle the call makes is inheritable.
    pub fn inherit(&self) -> bool {
        self.attributes & OBJ_INHERIT != 0
    }
}

/// Read the OBJECT_ATTRIBUTES at `at` and its name's units into `name`. STATUS_INVALID_PARAMETER
/// for a structure of another size, STATUS_NAME_TOO_LONG past [`MAX_NAME`] units.
pub fn read(at: UserAddr, name: &mut [u16; MAX_NAME]) -> Result<Attributes, NtStatus> {
    let mut raw = [0u8; OBJECT_ATTRIBUTES_SIZE as usize];
    at.read(&mut raw)?;
    let word = |i: usize| u32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
    if word(0) != OBJECT_ATTRIBUTES_SIZE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let string = UserAddr(word(8));
    let length = if string.is_null() {
        None
    } else {
        let mut header = [0u8; 8];
        string.read(&mut header)?;
        let bytes = u16::from_le_bytes([header[0], header[1]]) as usize;
        let buffer = UserAddr(u32::from_le_bytes([
            header[4], header[5], header[6], header[7],
        ]));
        let length = bytes / 2;
        if length > MAX_NAME {
            return Err(STATUS_NAME_TOO_LONG);
        }
        let mut units = [0u8; 2 * MAX_NAME];
        buffer.read(&mut units[..2 * length])?;
        for (unit, pair) in name.iter_mut().zip(units[..2 * length].chunks_exact(2)) {
            *unit = u16::from_le_bytes([pair[0], pair[1]]);
        }
        Some(length)
    };
    Ok(Attributes {
        root: word(4),
        length,
        attributes: word(12),
    })
}

/// The named objects' directory, by its full name.
const NAMED_OBJECTS: &str = "\\BaseNamedObjects";

/// Whether `units` begin with `prefix` (ASCII, case-insensitively, as the object manager looks up
/// directory names).
fn starts_with(units: &[u16], prefix: &str) -> bool {
    units.len() >= prefix.len()
        && units
            .iter()
            .zip(prefix.bytes())
            .all(|(&unit, byte)| unit < 0x80 && (unit as u8).eq_ignore_ascii_case(&byte))
}

/// Where a name resolves in the object namespace.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolved {
    /// `\BaseNamedObjects` itself.
    Directory,
    /// An object in `\BaseNamedObjects`, by its name there: the units after the directory's.
    Named { start: usize },
}

/// Resolve a name against its root: `root_is_directory` says the RootDirectory handle (nonzero)
/// names `\BaseNamedObjects`. A name relative to it must not start with a separator; an absolute
/// one (no root) must be in `\BaseNamedObjects` — any other directory is not there
/// (STATUS_OBJECT_PATH_NOT_FOUND), and a name not starting with a separator is no path at all
/// (STATUS_OBJECT_PATH_SYNTAX_BAD).
pub fn resolve(units: &[u16], root: u32, root_is_directory: bool) -> Result<Resolved, NtStatus> {
    let separator = u16::from(b'\\');
    if root != 0 {
        if !root_is_directory {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        if units.first() == Some(&separator) {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        return Ok(if units.is_empty() {
            Resolved::Directory
        } else {
            Resolved::Named { start: 0 }
        });
    }
    if units.first() != Some(&separator) {
        return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
    }
    if !starts_with(units, NAMED_OBJECTS) {
        return Err(STATUS_OBJECT_PATH_NOT_FOUND);
    }
    let rest = &units[NAMED_OBJECTS.len()..];
    match rest {
        [] => Ok(Resolved::Directory),
        [unit, ..] if *unit == separator && rest.len() > 1 => Ok(Resolved::Named {
            start: NAMED_OBJECTS.len() + 1,
        }),
        [unit] if *unit == separator => Ok(Resolved::Directory),
        _ => Err(STATUS_OBJECT_PATH_NOT_FOUND),
    }
}

/// An object's name in `\BaseNamedObjects`, as the namespace keeps it: code page 1252 bytes into
/// `out`, its length. `Global\` and `Local\` are the directory's links to itself (one session);
/// a separator past them names a subdirectory there is none of
/// (STATUS_OBJECT_PATH_NOT_FOUND). A character the namespace's bytes cannot hold is
/// STATUS_OBJECT_NAME_INVALID, and so is a name longer than [`crate::ob::MAX_NAME`].
pub fn object_name(units: &[u16], out: &mut [u8; crate::ob::MAX_NAME]) -> Result<usize, NtStatus> {
    if units.len() > out.len() {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    for (byte, &unit) in out.iter_mut().zip(units) {
        let narrow = rtl::cp1252::wc_to_mb(unit);
        if rtl::cp1252::MB_TO_WC[narrow as usize] != unit {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        *byte = narrow;
    }
    let name = crate::ob::namespace_name(&out[..units.len()]);
    if name.contains(&b'\\') {
        return Err(STATUS_OBJECT_PATH_NOT_FOUND);
    }
    if name.is_empty() {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    Ok(units.len())
}

/// What an OBJECT_ATTRIBUTES' RootDirectory handle names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Root {
    /// No root: the name is absolute.
    None,
    /// `\BaseNamedObjects`.
    NamedObjects,
    /// A file object (a directory's, for a name relative to it).
    #[cfg(target_arch = "x86")]
    File(crate::ob::ObjectId),
    /// Any other object.
    Other,
}

/// What `handle` names in the calling process, as a root directory: `\BaseNamedObjects` for a
/// handle to the directory object (NtOpenDirectoryObject's), the file object of a directory the
/// file services name relative to (ntdll's names under the current directory, see
/// `nt::file::name`); STATUS_INVALID_HANDLE for a handle naming nothing (a console handle
/// included).
#[cfg(target_arch = "x86")]
pub fn root_of(handle: u32) -> Result<Root, NtStatus> {
    if handle == 0 {
        return Ok(Root::None);
    }
    if crate::nt::object::is_console_handle(handle) {
        return Err(STATUS_INVALID_HANDLE);
    }
    let entry = super::call::calling_process()
        .handles()
        .lookup(handle)
        .ok_or(STATUS_INVALID_HANDLE)?;
    Ok(match entry.object_id() {
        Some(id) if id.kind == crate::ob::ObjectType::Directory => Root::NamedObjects,
        Some(id) if id.kind == crate::ob::ObjectType::File => Root::File(id),
        _ => Root::Other,
    })
}

/// Host builds have no handle table: any root names `\BaseNamedObjects`.
#[cfg(not(target_arch = "x86"))]
pub fn root_of(handle: u32) -> Result<Root, NtStatus> {
    let _ = STATUS_INVALID_HANDLE;
    Ok(if handle == 0 {
        Root::None
    } else {
        Root::NamedObjects
    })
}

/// Whether `handle` names `\BaseNamedObjects` in the calling process (see [`root_of`]).
pub fn root_is_directory(handle: u32) -> Result<bool, NtStatus> {
    Ok(root_of(handle)? == Root::NamedObjects)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn names_resolve_in_the_named_objects_directory() {
        assert_eq!(
            resolve(&wide("\\BaseNamedObjects\\E"), 0, false),
            Ok(Resolved::Named { start: 18 })
        );
        assert_eq!(
            resolve(&wide("\\basenamedobjects"), 0, false),
            Ok(Resolved::Directory)
        );
        assert_eq!(
            resolve(&wide("E"), 4, true),
            Ok(Resolved::Named { start: 0 })
        );
        assert_eq!(
            resolve(&wide("E"), 4, false),
            Err(STATUS_OBJECT_TYPE_MISMATCH)
        );
        assert_eq!(
            resolve(&wide("\\E"), 4, true),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(
            resolve(&wide("E"), 0, false),
            Err(STATUS_OBJECT_PATH_SYNTAX_BAD)
        );
        assert_eq!(
            resolve(&wide("\\Device\\E"), 0, false),
            Err(STATUS_OBJECT_PATH_NOT_FOUND)
        );
        assert_eq!(
            resolve(&wide("\\BaseNamedObjectsX"), 0, false),
            Err(STATUS_OBJECT_PATH_NOT_FOUND)
        );
    }

    #[test]
    fn object_names_are_the_namespace_bytes() {
        let mut out = [0u8; crate::ob::MAX_NAME];
        assert_eq!(object_name(&wide("Global\\E"), &mut out), Ok(8));
        assert_eq!(&out[..8], b"Global\\E");
        assert_eq!(
            object_name(&wide("a\\b"), &mut out),
            Err(STATUS_OBJECT_PATH_NOT_FOUND)
        );
        assert_eq!(
            object_name(&wide("\u{4E2D}"), &mut out),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(object_name(&wide("caf\u{E9}"), &mut out), Ok(4));
    }
}
