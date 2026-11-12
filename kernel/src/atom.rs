//! The global atom table: the table kernel32's GlobalAddAtom, GlobalFindAtom, GlobalDeleteAtom and
//! GlobalGetAtomName reach through the atom services (`nt::atom`: NtAddAtom, NtFindAtom,
//! NtDeleteAtom, NtQueryInformationAtom), as Windows 2000's executive keeps it for the window
//! station, with RtlAddAtomToAtomTable's family over it ([`AtomTable`]). F2K has one window
//! station, so one table, shared by every process; nothing a process ends removes its atoms.
//!
//! An atom is 16 bits. Below 0xC000 it is an integer atom: its value is its name ("#123" names 123,
//! leading zeros allowed), valid from 1 to 0xBFFF, and the table never stores one: adding or
//! finding one answers its value, deleting one succeeds and changes nothing. A name of '#' and
//! decimal digits alone is an integer atom's, refused (STATUS_INVALID_PARAMETER) when its value is
//! 0 or 0xC000 and above, "#" alone included; any other name ("#12a", "#-1", "# 12") is a string's.
//! From 0xC000 an atom is a string atom, an entry of the table: its name, 1 to 255 UTF-16 units
//! (STATUS_OBJECT_NAME_INVALID for an empty one, STATUS_INVALID_PARAMETER for a longer one), and
//! its reference count, which each add of the name counts up and each delete down, the entry going
//! at zero (a deleted or never-made string atom is STATUS_INVALID_HANDLE). Names match without
//! regard to the case of ASCII letters alone, as the atom fixture's capture shows:
//! "F2KAtomFixtureÉ" does not find "F2KAtomFixtureé". A name the table does not hold is
//! STATUS_OBJECT_NAME_NOT_FOUND.
//!
//! win32k's class and message atoms (`win32k::class`) are a table of their own, as Windows 2000's
//! window manager keeps its own atom table apart from the global one: the two never meet.
//!
//! The entries' records are the lock's value; their names live in a block of the nonpaged pool,
//! one slot of [`MAX_NAME`] units per entry, taken when the table's first string atom is added and
//! given back when its last goes (Windows 2000 takes each entry from its pool as it is made and
//! frees it with the entry). Like the clipboard's data, the block outlives the process that made
//! its atoms: a program that ends with atoms of its own in the table leaves the block taken.

use crate::level::{At, Passive};
use crate::status::*;
use crate::sync::ShortLock;

/// An atom: an integer atom below [`FIRST_STRING_ATOM`], a string atom from it.
pub type Atom = u16;

/// The first string atom; every integer atom is below it (MAXINTATOM).
pub const FIRST_STRING_ATOM: Atom = 0xC000;
/// The longest atom name, in UTF-16 units.
pub const MAX_NAME: usize = 255;
/// How many string atoms the table holds.
const CAPACITY: usize = 512;
/// The bytes a name's slot takes in the names' block.
const SLOT: usize = 512;

/// RTL_ATOM_PINNED: an atom that cannot be deleted. Integer atoms report it.
pub const RTL_ATOM_PINNED: u16 = 0x01;

/// The names' block: a block of the nonpaged pool (on the host, a vector).
#[cfg(target_arch = "x86")]
type Block = crate::mem::pool::Block;
#[cfg(not(target_arch = "x86"))]
type Block = std::vec::Vec<u8>;

/// A zeroed block for the names; none when the pool has no room.
fn allocate_names() -> Option<Block> {
    #[cfg(target_arch = "x86")]
    {
        crate::mem::pool::allocate(CAPACITY * SLOT)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        Some(std::vec![0; CAPACITY * SLOT])
    }
}

/// A block's bytes.
fn bytes(block: &Block) -> &[u8] {
    block.as_ref()
}

/// A block's bytes, to write.
fn bytes_mut(block: &mut Block) -> &mut [u8] {
    block.as_mut()
}

/// What a name names: an integer atom's value, or a string atom's name to look up.
enum Named<'a> {
    Integer(Atom),
    Text(&'a [u16]),
}

/// Judge a name: an integer atom's ('#' and decimal digits alone, its value from 1 to 0xBFFF) or a
/// string atom's (1 to [`MAX_NAME`] units).
fn named(name: &[u16]) -> Result<Named<'_>, NtStatus> {
    if name.is_empty() {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    if name.len() > MAX_NAME {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if let Some(value) = integer_value(name) {
        return match value {
            1..0xC000 => Ok(Named::Integer(value as Atom)),
            _ => Err(STATUS_INVALID_PARAMETER),
        };
    }
    Ok(Named::Text(name))
}

/// The value of a name of '#' and decimal digits alone (0 for "#"; past 0xFFFF it stops counting
/// at 0x10000); none for another name.
fn integer_value(name: &[u16]) -> Option<u32> {
    let (&first, digits) = name.split_first()?;
    if first != u16::from(b'#') {
        return None;
    }
    digits.iter().try_fold(0u32, |value, &unit| {
        let digit = u32::from(unit).wrapping_sub(u32::from(b'0'));
        (digit <= 9).then(|| (value * 10 + digit).min(0x1_0000))
    })
}

/// Whether two names match: unit for unit, ASCII letters in either case.
fn same_name(a: impl Iterator<Item = u16>, b: &[u16]) -> bool {
    let fold = |unit: u16| match unit {
        0x61..=0x7A => unit - 0x20,
        _ => unit,
    };
    let mut count = 0;
    for (x, &y) in a.zip(b) {
        if fold(x) != fold(y) {
            return false;
        }
        count += 1;
    }
    count == b.len()
}

/// The decimal digits of an integer atom's name ("#" and its value).
fn integer_name(atom: Atom, out: &mut [u16; 6]) -> usize {
    let mut digits = [0u16; 5];
    let mut count = 0;
    let mut value = atom;
    loop {
        digits[count] = u16::from(b'0') + value % 10;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    out[0] = u16::from(b'#');
    for (at, &digit) in digits[..count].iter().rev().enumerate() {
        out[1 + at] = digit;
    }
    count + 1
}

/// One entry's record: its name's length (0 for a free entry) and its reference count.
#[derive(Clone, Copy)]
struct Entry {
    length: u16,
    references: u16,
}

impl Entry {
    const FREE: Entry = Entry {
        length: 0,
        references: 0,
    };

    fn is_live(&self) -> bool {
        self.length != 0
    }
}

/// What NtQueryInformationAtom's ATOM_BASIC_INFORMATION reports of an atom besides its name: its
/// usage count and flags, and the units of its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtomFacts {
    pub usage: u16,
    pub flags: u16,
    pub length: usize,
}

/// An atom table: the entries' records and the block their names live in (RTL_ATOM_TABLE's work;
/// see the module notes).
pub struct AtomTable {
    entries: [Entry; CAPACITY],
    names: Option<Block>,
}

impl AtomTable {
    /// An empty table: no block yet.
    pub const fn new() -> Self {
        AtomTable {
            entries: [Entry::FREE; CAPACITY],
            names: None,
        }
    }

    /// The units of entry `index`'s name.
    fn name(&self, index: usize) -> impl Iterator<Item = u16> + '_ {
        let length = usize::from(self.entries[index].length);
        let bytes = match &self.names {
            Some(block) => &bytes(block)[index * SLOT..index * SLOT + 2 * length],
            None => &[][..],
        };
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
    }

    /// The entry holding `name`, if any.
    fn entry_of(&self, name: &[u16]) -> Option<usize> {
        (0..CAPACITY).find(|&index| {
            let entry = &self.entries[index];
            entry.is_live()
                && usize::from(entry.length) == name.len()
                && same_name(self.name(index), name)
        })
    }

    /// The entry a string atom names, if it is live.
    fn entry_at(&self, atom: Atom) -> Option<usize> {
        let index = usize::from(atom.checked_sub(FIRST_STRING_ATOM)?);
        (index < CAPACITY && self.entries[index].is_live()).then_some(index)
    }

    /// RtlAddAtomToAtomTable: the atom of `name`, a string atom's reference counted (its entry made
    /// for a new name, under the case it was first added in); STATUS_NO_MEMORY when the table or
    /// the pool is full.
    pub fn add(&mut self, name: &[u16]) -> Result<Atom, NtStatus> {
        let name = match named(name)? {
            Named::Integer(atom) => return Ok(atom),
            Named::Text(name) => name,
        };
        if let Some(index) = self.entry_of(name) {
            let entry = &mut self.entries[index];
            entry.references = entry.references.saturating_add(1);
            return Ok(FIRST_STRING_ATOM + index as Atom);
        }
        let index = (0..CAPACITY)
            .find(|&index| !self.entries[index].is_live())
            .ok_or(STATUS_NO_MEMORY)?;
        if self.names.is_none() {
            self.names = Some(allocate_names().ok_or(STATUS_NO_MEMORY)?);
        }
        let block = bytes_mut(self.names.as_mut().expect("allocated above"));
        for (at, unit) in name.iter().enumerate() {
            let offset = index * SLOT + 2 * at;
            block[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        self.entries[index] = Entry {
            length: name.len() as u16,
            references: 1,
        };
        Ok(FIRST_STRING_ATOM + index as Atom)
    }

    /// RtlLookupAtomInAtomTable: the atom of `name`, its reference count untouched.
    pub fn lookup(&self, name: &[u16]) -> Result<Atom, NtStatus> {
        match named(name)? {
            Named::Integer(atom) => Ok(atom),
            Named::Text(name) => self
                .entry_of(name)
                .map(|index| FIRST_STRING_ATOM + index as Atom)
                .ok_or(STATUS_OBJECT_NAME_NOT_FOUND),
        }
    }

    /// RtlDeleteAtomFromAtomTable: a string atom's reference given back, its entry going with the
    /// last (and the names' block with the table's last entry); an integer atom changes nothing.
    /// STATUS_INVALID_PARAMETER for atom 0.
    pub fn delete(&mut self, atom: Atom) -> Result<(), NtStatus> {
        match atom {
            0 => Err(STATUS_INVALID_PARAMETER),
            1..FIRST_STRING_ATOM => Ok(()),
            _ => {
                let index = self.entry_at(atom).ok_or(STATUS_INVALID_HANDLE)?;
                let entry = &mut self.entries[index];
                entry.references -= 1;
                if entry.references == 0 {
                    *entry = Entry::FREE;
                    if self.count() == 0 {
                        self.names = None;
                    }
                }
                Ok(())
            }
        }
    }

    /// RtlQueryAtomInAtomTable: an atom's facts, and as much of its name as `out` holds written
    /// there (an integer atom's is "#" and its value, its usage 1, pinned).
    /// STATUS_INVALID_PARAMETER for atom 0.
    pub fn query(&self, atom: Atom, out: &mut [u16]) -> Result<AtomFacts, NtStatus> {
        match atom {
            0 => Err(STATUS_INVALID_PARAMETER),
            1..FIRST_STRING_ATOM => {
                let mut name = [0u16; 6];
                let length = integer_name(atom, &mut name);
                let copied = length.min(out.len());
                out[..copied].copy_from_slice(&name[..copied]);
                Ok(AtomFacts {
                    usage: 1,
                    flags: RTL_ATOM_PINNED,
                    length,
                })
            }
            _ => {
                let index = self.entry_at(atom).ok_or(STATUS_INVALID_HANDLE)?;
                for (slot, unit) in out.iter_mut().zip(self.name(index)) {
                    *slot = unit;
                }
                let entry = &self.entries[index];
                Ok(AtomFacts {
                    usage: entry.references,
                    flags: 0,
                    length: usize::from(entry.length),
                })
            }
        }
    }

    /// How many string atoms the table holds.
    pub fn count(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_live()).count()
    }

    /// The string atoms of the entries from `first` on, into `out` (as many as it holds); how many
    /// it wrote, and the entry the next call starts at.
    pub fn atoms_from(&self, first: usize, out: &mut [Atom]) -> (usize, usize) {
        let mut written = 0;
        let mut index = first;
        while index < CAPACITY && written < out.len() {
            if self.entries[index].is_live() {
                out[written] = FIRST_STRING_ATOM + index as Atom;
                written += 1;
            }
            index += 1;
        }
        (written, index)
    }
}

/// The window station's table, behind its lock (Windows 2000 guards an RTL_ATOM_TABLE with a fast
/// mutex, held for each call into it, never across a wait or a user-memory copy).
static GLOBAL: ShortLock<AtomTable> = ShortLock::new(AtomTable::new());

/// The global table, under its lock, for the length of `work`.
pub fn with_global<R>(passive: &mut At<Passive>, work: impl FnOnce(&mut AtomTable) -> R) -> R {
    let mut table = GLOBAL.lock(passive);
    work(&mut table)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
    }

    /// The atom fixture's add section: one atom whatever the ASCII case, four references; é and É
    /// two names.
    #[test]
    fn names_fold_ascii_case_alone() {
        let mut table = AtomTable::new();
        let first = table.add(&units("F2KAtomFixtureOne")).unwrap();
        assert!(first >= FIRST_STRING_ATOM);
        assert_eq!(table.add(&units("F2KATOMFIXTUREONE")), Ok(first));
        assert_eq!(table.lookup(&units("f2katomfixtureone")), Ok(first));
        let mut name = [0u16; 64];
        let facts = table.query(first, &mut name).unwrap();
        assert_eq!((facts.usage, facts.length), (2, 17));
        assert_eq!(&name[..17], &units("F2KAtomFixtureOne")[..]);
        let accent = table.add(&units("F2KAtomFixtureé")).unwrap();
        assert_eq!(
            table.lookup(&units("F2KAtomFixtureÉ")),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_ne!(accent, first);
    }

    /// The refcount section: deleted after as many deletions as adds, then STATUS_INVALID_HANDLE.
    #[test]
    fn deletions_count_down() {
        let mut table = AtomTable::new();
        let name = units("F2KAtomFixtureCount");
        let atom = table.add(&name).unwrap();
        table.add(&name).unwrap();
        assert_eq!(table.delete(atom), Ok(()));
        assert_eq!(table.lookup(&name), Ok(atom));
        assert_eq!(table.delete(atom), Ok(()));
        assert_eq!(table.lookup(&name), Err(STATUS_OBJECT_NAME_NOT_FOUND));
        assert_eq!(table.delete(atom), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.query(atom, &mut []), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.count(), 0);
        assert!(table.names.is_none(), "the block goes with the last entry");
    }

    /// The integer section: "#ddddd" from 1 to 0xBFFF is an integer atom, never stored; "#" and the
    /// values outside it refused; names that only look like numbers are strings.
    #[test]
    fn integer_atoms() {
        let mut table = AtomTable::new();
        assert_eq!(table.add(&units("#123")), Ok(123));
        assert_eq!(table.add(&units("#00123")), Ok(123));
        assert_eq!(table.lookup(&units("#456")), Ok(456));
        assert_eq!(table.add(&units("#49151")), Ok(49151));
        for refused in ["#0", "#49152", "#65535", "#65536", "#", "#99999999999"] {
            assert_eq!(
                table.add(&units(refused)),
                Err(STATUS_INVALID_PARAMETER),
                "{refused}"
            );
        }
        for string in ["#12a", "#-1", "# 12"] {
            assert!(table.add(&units(string)).unwrap() >= FIRST_STRING_ATOM);
        }
        assert_eq!(table.count(), 3);
        assert_eq!(table.delete(123), Ok(()));
        let mut name = [0u16; 3];
        let facts = table.query(123, &mut name).unwrap();
        assert_eq!((facts.length, facts.flags), (4, RTL_ATOM_PINNED));
        assert_eq!(name, [b'#' as u16, b'1' as u16, b'2' as u16]);
        let mut name = [0u16; 8];
        assert_eq!(table.query(49151, &mut name).unwrap().length, 6);
        assert_eq!(table.query(0, &mut name), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(table.delete(0), Err(STATUS_INVALID_PARAMETER));
    }

    /// The length and errors sections: 255 units fit, 256 do not; an empty name is invalid.
    #[test]
    fn name_lengths() {
        let mut table = AtomTable::new();
        let long: std::vec::Vec<u16> = std::iter::repeat_n(b'x' as u16, 255).collect();
        let atom = table.add(&long).unwrap();
        let mut name = [0u16; 255];
        assert_eq!(table.query(atom, &mut name).unwrap().length, 255);
        assert_eq!(&name[..], &long[..]);
        let longer: std::vec::Vec<u16> = std::iter::repeat_n(b'x' as u16, 256).collect();
        assert_eq!(table.add(&longer), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(table.lookup(&longer), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(table.add(&[]), Err(STATUS_OBJECT_NAME_INVALID));
        assert_eq!(table.lookup(&[]), Err(STATUS_OBJECT_NAME_INVALID));
    }

    /// A full table answers STATUS_NO_MEMORY; a freed entry is reused; the listing walks the live
    /// entries.
    #[test]
    fn a_full_table() {
        let mut table = AtomTable::new();
        for n in 0..CAPACITY {
            table.add(&units(&std::format!("name{n}"))).unwrap();
        }
        assert_eq!(table.add(&units("one more")), Err(STATUS_NO_MEMORY));
        table.delete(FIRST_STRING_ATOM + 7).unwrap();
        assert_eq!(table.add(&units("one more")), Ok(FIRST_STRING_ATOM + 7));
        let mut atoms = [0; 4];
        assert_eq!(table.atoms_from(CAPACITY - 2, &mut atoms), (2, CAPACITY));
        assert_eq!(&atoms[..2], &[0xC000 + 510, 0xC000 + 511]);
    }
}
