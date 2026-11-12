//! The atom services: NtAddAtom, NtFindAtom, NtDeleteAtom and NtQueryInformationAtom, over the
//! window station's global atom table ([`crate::atom`]). kernel32's GlobalAddAtom family is Win32
//! code over them, as on Windows 2000; an integer atom given as a number (MAKEINTATOM) never
//! reaches them, kernel32 answering it itself.
//!
//! A name is the caller's UTF-16 units and their length in bytes (an odd byte ignored), copied
//! into a kernel buffer before the table's lock is taken: a name past 255 units is
//! STATUS_INVALID_PARAMETER before anything is read. The atom an add or a find answers goes to the
//! caller's RTL_ATOM, when it gives one.

use super::call::{NtCall, NtResult, UserAddr, UserPtr};
use crate::atom::{self, Atom, MAX_NAME};
use crate::status::*;

info_class! {
    /// The atom information classes (ATOM_INFORMATION_CLASS).
    pub enum AtomClass {
        Basic = 0,
        Table = 1,
    }
}

/// ATOM_BASIC_INFORMATION's size (its name's first unit included, padded to the structure's
/// alignment), and its name's offset: UsageCount, Flags and NameLength come first, a USHORT each.
const BASIC_SIZE: u32 = 8;
const BASIC_NAME: u32 = 6;
/// ATOM_TABLE_INFORMATION's atoms' offset: NumberOfAtoms, a ULONG, comes first.
const TABLE_ATOMS: u32 = 4;
/// The atoms ATOM_TABLE_INFORMATION's listing copies out at a time.
const LISTING_CHUNK: usize = 128;

/// The caller's name, `length` bytes at `name`, copied into `units`: the units it fills.
fn read_name(name: UserAddr, length: u32, units: &mut [u16; MAX_NAME]) -> Result<&[u16], NtStatus> {
    let count = (length / 2) as usize;
    if count > MAX_NAME {
        return Err(STATUS_INVALID_PARAMETER);
    }
    name.read_units(&mut units[..count])?;
    Ok(&units[..count])
}

/// NtAddAtom(AtomName, Length, Atom): the name added to the global table, the atom it has written
/// to Atom (see [`crate::atom::AtomTable::add`]).
pub fn add_atom(call: &mut NtCall, name: UserAddr, length: u32, atom: UserPtr<u16>) -> NtResult {
    let mut units = [0u16; MAX_NAME];
    let name = read_name(name, length, &mut units)?;
    let added = atom::with_global(call.passive(), |table| table.add(name))?;
    atom.write_optional(added)?;
    Ok(STATUS_SUCCESS)
}

/// NtFindAtom(AtomName, Length, Atom): the atom the name has in the global table, written to Atom;
/// STATUS_OBJECT_NAME_NOT_FOUND when it has none (see [`crate::atom::AtomTable::lookup`]).
pub fn find_atom(call: &mut NtCall, name: UserAddr, length: u32, atom: UserPtr<u16>) -> NtResult {
    let mut units = [0u16; MAX_NAME];
    let name = read_name(name, length, &mut units)?;
    let found = atom::with_global(call.passive(), |table| table.lookup(name))?;
    atom.write_optional(found)?;
    Ok(STATUS_SUCCESS)
}

/// NtDeleteAtom(Atom): one reference to a string atom given back (see
/// [`crate::atom::AtomTable::delete`]); the RTL_ATOM is the argument's low word.
pub fn delete_atom(call: &mut NtCall, atom: u32) -> NtResult {
    atom::with_global(call.passive(), |table| table.delete(atom as Atom))?;
    Ok(STATUS_SUCCESS)
}

/// NtQueryInformationAtom(Atom, AtomInformationClass, AtomInformation, AtomInformationLength,
/// ReturnLength): AtomBasicInformation ([`query_basic`]) or AtomTableInformation
/// ([`query_table`]), the bytes written (or, for a listing too long for the buffer, the bytes it
/// needs) going to ReturnLength when given; another class is STATUS_INVALID_INFO_CLASS.
pub fn query_information_atom(
    call: &mut NtCall,
    atom: u32,
    class: u32,
    information: UserAddr,
    length: u32,
    return_length: UserPtr<u32>,
) -> NtResult {
    match AtomClass::try_from(class)? {
        AtomClass::Basic => query_basic(call, atom as Atom, information, length, return_length),
        AtomClass::Table => query_table(call, information, length, return_length),
    }
}

/// ATOM_BASIC_INFORMATION: the atom's usage count, its flags (RTL_ATOM_PINNED for an integer
/// atom) and as much of its name as the buffer holds past the structure's fixed part, NameLength
/// its bytes, terminated when there is room for the terminator too. STATUS_INFO_LENGTH_MISMATCH for
/// a buffer shorter than the structure; the atom's own failures as the table answers them.
fn query_basic(
    call: &mut NtCall,
    atom: Atom,
    information: UserAddr,
    length: u32,
    return_length: UserPtr<u32>,
) -> NtResult {
    if length < BASIC_SIZE {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let room = (((length - BASIC_NAME) / 2) as usize).min(MAX_NAME + 1);
    let mut name = [0u16; MAX_NAME + 1];
    let facts = atom::with_global(call.passive(), |table| table.query(atom, &mut name))?;
    let copied = facts.length.min(room);
    let terminated = copied < room;
    if terminated {
        name[copied] = 0;
    }
    let units = copied + usize::from(terminated);
    let header = [facts.usage, facts.flags, (2 * copied) as u16];
    information.write(rtl::pod::Pod::as_bytes(&header))?;
    information
        .offset(BASIC_NAME)
        .write(&rtl::pod::Pod::as_bytes(&name)[..2 * units])?;
    return_length.write_optional(BASIC_NAME + 2 * units as u32)?;
    Ok(STATUS_SUCCESS)
}

/// ATOM_TABLE_INFORMATION: the table's string atoms and their number.
/// STATUS_INFO_LENGTH_MISMATCH for a buffer too short for them all, the bytes the listing needs
/// written to ReturnLength. The listing is copied out a chunk at a time, the lock taken for each,
/// so an atom added meanwhile may be left out (never one past the count first taken).
fn query_table(
    call: &mut NtCall,
    information: UserAddr,
    length: u32,
    return_length: UserPtr<u32>,
) -> NtResult {
    let count = atom::with_global(call.passive(), |table| table.count());
    let needed = TABLE_ATOMS + 2 * count as u32;
    if length < needed.max(BASIC_SIZE) {
        return_length.write_optional(needed.max(BASIC_SIZE))?;
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let mut chunk = [0u16; LISTING_CHUNK];
    let (mut written, mut next) = (0usize, 0usize);
    while written < count {
        let room = (count - written).min(LISTING_CHUNK);
        let (listed, after) = atom::with_global(call.passive(), |table| {
            table.atoms_from(next, &mut chunk[..room])
        });
        if listed == 0 {
            break;
        }
        information
            .offset(TABLE_ATOMS + 2 * written as u32)
            .write(&rtl::pod::Pod::as_bytes(&chunk)[..2 * listed])?;
        written += listed;
        next = after;
    }
    information.write(&(written as u32).to_le_bytes())?;
    return_length.write_optional(TABLE_ATOMS + 2 * written as u32)?;
    Ok(STATUS_SUCCESS)
}
