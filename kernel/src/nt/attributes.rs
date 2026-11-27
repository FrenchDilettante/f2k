//! OBJECT_ATTRIBUTES: what every service that names an object reads — the root directory handle,
//! the name (a UNICODE_STRING) and the attributes — and the named objects' part of the namespace,
//! `\BaseNamedObjects`, where kernel32 names its events, mutexes, semaphores and sections (and, as
//! they come, its timers).
//!
//! A name is absolute (`\BaseNamedObjects\<name>`, no root), or relative to a root directory
//! handle naming `\BaseNamedObjects`: the directory object kernel32 opens once
//! (BaseGetNamedObjectDirectory, NtOpenDirectoryObject) and names everything relative to, as on
//! Windows 2000 ([`root_of`]).

use core::mem::size_of;

use rtl::array_vec::ArrayVec;
use rtl::nt::{ObjectAttributes, UnicodeString};
// OBJECT_ATTRIBUTES' Attributes: OBJ_INHERIT, OBJ_CASE_INSENSITIVE and OBJ_OPENIF.
pub use rtl::nt::{OBJ_CASE_INSENSITIVE, OBJ_INHERIT, OBJ_OPENIF};

use super::call::UserAddr;
use crate::status::*;

/// OBJECT_ATTRIBUTES' size.
const OBJECT_ATTRIBUTES_SIZE: u32 = size_of::<ObjectAttributes<u32>>() as u32;

/// The longest name read, in units.
pub const MAX_NAME: usize = 1024;

/// The storage a name an OBJECT_ATTRIBUTES gives is read into: up to [`MAX_NAME`] units.
///
/// The caller holds it and [`read`]'s answer borrows it, rather than the answer owning it: a name
/// is 2 KiB, and the kernel's unoptimized build gives every copy of a returned value a stack slot
/// of its own (returned by value, a name overflowed NtOpenFile's gate stack).
pub type Name = ArrayVec<u16, MAX_NAME>;

/// An OBJECT_ATTRIBUTES, read: the root directory handle, the name (none for a null ObjectName),
/// the attributes, and the SecurityDescriptor pointer as the caller gave it.
pub struct Attributes<'n> {
    pub root: u32,
    pub name: Option<&'n [u16]>,
    pub attributes: u32,
    /// OBJECT_ATTRIBUTES' SecurityDescriptor: a pointer into the caller's memory, zero when none.
    /// A user-mode caller's is captured at once (see [`read`]). Read by the tests; the create and
    /// open services take the captured descriptor through [`crate::ob::security`] instead.
    #[cfg_attr(not(test), allow(dead_code))]
    pub security_descriptor: u32,
}

impl<'n> Attributes<'n> {
    /// Whether a handle the call makes is inheritable.
    pub fn inherit(&self) -> bool {
        self.attributes & OBJ_INHERIT != 0
    }

    /// Whether the name compares case-insensitively (OBJ_CASE_INSENSITIVE).
    pub fn case_insensitive(&self) -> bool {
        self.attributes & OBJ_CASE_INSENSITIVE != 0
    }

    /// The name's units: none for a null ObjectName, as for an empty name.
    pub fn units(&self) -> &'n [u16] {
        self.name.unwrap_or_default()
    }
}

/// Read the OBJECT_ATTRIBUTES at `at`, its name into `name` (whatever it held before dropped).
/// STATUS_INVALID_PARAMETER for a structure of another size, STATUS_NAME_TOO_LONG past
/// [`MAX_NAME`] units.
///
/// A user-mode caller's SecurityDescriptor (when the structure names one) is captured now —
/// probed and copied out of its memory, self-relative, into the pending descriptor the create
/// or open this read is part of stores on the object it makes (see [`crate::ob::security`]); a
/// capture failure fails the read with its status. A kernel-mode caller's is left as it is.
pub fn read(at: UserAddr, name: &mut Name) -> Result<Attributes<'_>, NtStatus> {
    let header = at.cast::<ObjectAttributes<u32>>().read()?;
    if header.length != OBJECT_ATTRIBUTES_SIZE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    name.clear();
    let string = UserAddr(header.object_name);
    let named = !string.is_null();
    if named {
        let string = string.cast::<UnicodeString<u32>>().read()?;
        let units = name
            .try_extend_default(usize::from(string.length) / 2)
            .map_err(|_| STATUS_NAME_TOO_LONG)?;
        UserAddr(string.buffer).read_units(units)?;
    }
    // The security descriptor the caller passed, captured for the create or open to come: the
    // pending slot is cleared first, so a read that captures nothing leaves none behind.
    let security_descriptor = header.security_descriptor;
    crate::ob::security::set_pending(None);
    if security_descriptor != 0
        && crate::ob::security::caller_mode() == crate::sec::CallerMode::User
    {
        if let Some(captured) = crate::ob::security::capture_sd(security_descriptor, true)? {
            crate::ob::security::set_pending(Some(captured));
        }
    }
    Ok(Attributes {
        root: header.root_directory,
        name: named.then_some(name.as_slice()),
        attributes: header.attributes,
        security_descriptor,
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

/// An object's name in `\BaseNamedObjects`, as the namespace keeps it: the UTF-16 units the
/// caller's UNICODE_STRING gave.
pub type ObjectName = ArrayVec<u16, { crate::ob::MAX_NAME }>;

/// The namespace's units for an object's name in `\BaseNamedObjects`: any units, as Windows 2000's
/// object manager keeps a UNICODE_STRING (none is translated or refused for its value).
/// `Global\` and `Local\` are the directory's links to itself (one session); a separator past them
/// names a subdirectory there is none of (STATUS_OBJECT_PATH_NOT_FOUND). An empty name, or one
/// longer than [`crate::ob::MAX_NAME`], is STATUS_OBJECT_NAME_INVALID.
pub fn object_name(units: &[u16]) -> Result<ObjectName, NtStatus> {
    let mut out = ObjectName::new();
    out.try_extend_from_slice(units)
        .map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
    let name = crate::ob::namespace_name(&out);
    if name.contains(&u16::from(b'\\')) {
        return Err(STATUS_OBJECT_PATH_NOT_FOUND);
    }
    if name.is_empty() {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    Ok(out)
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
        .lookup_handle(handle)
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
    use rtl::testing::wide;

    use super::*;

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

    /// An object's name is its units as given, whatever they are: a CJK name, a surrogate pair, a
    /// lone surrogate and a Latin-1 letter alike (Windows 2000 keeps a UNICODE_STRING).
    #[test]
    fn object_names_are_the_units_given() {
        assert_eq!(
            object_name(&wide("Global\\E")).as_deref(),
            Ok(&wide("Global\\E")[..])
        );
        assert_eq!(
            object_name(&wide("a\\b")),
            Err(STATUS_OBJECT_PATH_NOT_FOUND)
        );
        assert_eq!(
            object_name(&wide("\u{4E8B}\u{4EF6}")).as_deref(),
            Ok(&[0x4E8B, 0x4EF6][..])
        );
        assert_eq!(
            object_name(&wide("caf\u{E9}")).as_deref(),
            Ok(&wide("caf\u{E9}")[..])
        );
        assert_eq!(
            object_name(&wide("\u{1F600}")).as_deref(),
            Ok(&[0xD83D, 0xDE00][..])
        );
        assert_eq!(object_name(&[0xDC00]).as_deref(), Ok(&[0xDC00][..]));
        assert_eq!(
            object_name(&wide("Local\\")),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(
            object_name(&[u16::from(b'a'); crate::ob::MAX_NAME]).map(|name| name.len()),
            Ok(crate::ob::MAX_NAME)
        );
        assert_eq!(
            object_name(&[u16::from(b'a'); crate::ob::MAX_NAME + 1]),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
    }

    /// An OBJECT_ATTRIBUTES reads whole, its name (a UNICODE_STRING) with it: a structure of
    /// another length is refused, a name past the longest is too long, a null name is none.
    #[test]
    fn attributes_read_with_their_name() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use rtl::pod::Pod;

        use crate::user::syscall::host::{install, UserMemory};
        const BASE: u32 = 0x10000;
        struct Page(std::vec::Vec<u8>);
        impl UserMemory for Page {
            fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), NtStatus> {
                let at = pointer.checked_sub(BASE).ok_or(STATUS_ACCESS_VIOLATION)? as usize;
                let from = self.0.get(at..at + bytes.len());
                bytes.copy_from_slice(from.ok_or(STATUS_ACCESS_VIOLATION)?);
                Ok(())
            }

            fn write(&mut self, _: u32, _: &[u8]) -> Result<(), NtStatus> {
                Err(STATUS_ACCESS_VIOLATION)
            }
        }
        // The attributes at BASE, their UNICODE_STRING at +0x20, its units at +0x40.
        let mut page = std::vec![0u8; 0x1000];
        let attributes = ObjectAttributes::<u32> {
            length: 24,
            root_directory: 0x10,
            object_name: BASE + 0x20,
            attributes: OBJ_INHERIT | OBJ_OPENIF,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };
        page[..24].copy_from_slice(attributes.as_bytes());
        let string = UnicodeString::<u32> {
            length: 6,
            maximum_length: 8,
            buffer: BASE + 0x40,
        };
        page[0x20..0x28].copy_from_slice(string.as_bytes());
        page[0x40..0x46].copy_from_slice(b"E\0v\0t\0");
        let memory = Rc::new(RefCell::new(Page(page)));
        let _installed = install(memory.clone());

        let mut name = Name::new();
        let got = read(UserAddr(BASE), &mut name).unwrap();
        assert_eq!(got.root, 0x10);
        assert!(got.inherit() && got.attributes & OBJ_OPENIF != 0);
        assert_eq!(got.name, Some(&wide("Evt")[..]));
        assert_eq!(got.units(), &wide("Evt")[..]);

        // Too long: one unit past the longest.
        let long = (2 * (MAX_NAME + 1)) as u16;
        memory.borrow_mut().0[0x20..0x22].copy_from_slice(&long.to_le_bytes());
        assert_eq!(
            read(UserAddr(BASE), &mut name).map(|got| got.name),
            Err(STATUS_NAME_TOO_LONG)
        );
        // No name.
        memory.borrow_mut().0[8..12].fill(0);
        assert_eq!(
            read(UserAddr(BASE), &mut name).map(|got| got.name),
            Ok(None)
        );
        // Another structure's length.
        memory.borrow_mut().0[0] = 28;
        assert_eq!(
            read(UserAddr(BASE), &mut name).map(|got| got.name),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            read(UserAddr(BASE + 0xFF8), &mut name).map(|got| got.name),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }

    /// The SecurityDescriptor pointer reads as the caller gave it: zero when none, the pointer
    /// when given (a host build serves no user caller, so nothing is captured from it).
    #[test]
    fn attributes_read_their_security_descriptor_pointer() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use rtl::pod::Pod;

        use crate::user::syscall::host::{install, UserMemory};
        const BASE: u32 = 0x20000;
        struct Page(std::vec::Vec<u8>);
        impl UserMemory for Page {
            fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), NtStatus> {
                let at = pointer.checked_sub(BASE).ok_or(STATUS_ACCESS_VIOLATION)? as usize;
                bytes.copy_from_slice(
                    self.0.get(at..at + bytes.len()).ok_or(STATUS_ACCESS_VIOLATION)?,
                );
                Ok(())
            }

            fn write(&mut self, _: u32, _: &[u8]) -> Result<(), NtStatus> {
                Err(STATUS_ACCESS_VIOLATION)
            }
        }
        let mut page = std::vec![0u8; 0x100];
        let attributes = ObjectAttributes::<u32> {
            length: 24,
            root_directory: 0,
            object_name: 0,
            attributes: 0,
            security_descriptor: 0x5000,
            security_quality_of_service: 0,
        };
        page[..24].copy_from_slice(attributes.as_bytes());
        let memory = Rc::new(RefCell::new(Page(page)));
        let _installed = install(memory);
        let mut name = Name::new();
        let got = read(UserAddr(BASE), &mut name).unwrap();
        assert_eq!(got.security_descriptor, 0x5000);
        assert_eq!(got.name, None);
        // None given: zero.
        let page = std::vec![0u8; 0x100];
        let attributes = ObjectAttributes::<u32> {
            length: 24,
            root_directory: 0,
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };
        let mut page = page;
        page[..24].copy_from_slice(attributes.as_bytes());
        let memory = Rc::new(RefCell::new(Page(page)));
        let _installed = install(memory);
        let got = read(UserAddr(BASE), &mut name).unwrap();
        assert_eq!(got.security_descriptor, 0);
    }
}
