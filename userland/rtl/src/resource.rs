//! Resources: an image's resource directory, walked as Windows 2000's ntdll walks it
//! (LdrFindResource_U, LdrFindResourceDirectory_U, LdrAccessResource), and the message tables
//! (RT_MESSAGETABLE resources) RtlFindMessage looks a message up in — kernel32's system messages
//! among them.
//!
//! The layouts are winnt.h's. The resource directory (the optional header's third data directory)
//! is a tree of IMAGE_RESOURCE_DIRECTORY tables, three levels deep as the resource compiler writes
//! it: the types, each type's names, each name's languages. A table's entries (named ones first,
//! then the numbered ones) name a subtable or, at the last level, an IMAGE_RESOURCE_DATA_ENTRY,
//! whose OffsetToData is the data's RVA. A MESSAGE_RESOURCE_DATA holds blocks of consecutive
//! message identifiers, each block's MESSAGE_RESOURCE_ENTRY records in a row: a length (the record
//! whole), flags (1: the text is UTF-16), and the text, padded with NULs to a dword.
//!
//! A path element (ULONG_PTR, as LdrFindResource_U takes them) is a numbered identifier when its
//! high word is zero (IS_INTRESOURCE), else the address of a NUL-terminated UTF-16 name, matched
//! exactly against the table's names. The third element, a language, is searched as the
//! FormatMessage documentation describes ([`languages`]).
//!
//! The reads go through [`Memory`], by 32-bit user address: the process's own memory on the target,
//! a model in the tests.

use crate::modules::Memory;
/// The resource type of a message table: RT_MESSAGETABLE.
pub const RT_MESSAGETABLE: u32 = 11;
/// The name a message-table resource has: the message compiler writes one, numbered 1.
pub const MESSAGE_TABLE_NAME: u32 = 1;
/// MESSAGE_RESOURCE_ENTRY's Flags: MESSAGE_RESOURCE_UNICODE, the text is UTF-16.
pub const MESSAGE_RESOURCE_UNICODE: u16 = 0x0001;

/// The statuses of a resource that is not there: no resource directory (or a data entry where a
/// table should be, or the reverse), no such type, no such name, no such language; and a message
/// table without the identifier.
pub const STATUS_RESOURCE_DATA_NOT_FOUND: u32 = 0xC000_0089;
pub const STATUS_RESOURCE_TYPE_NOT_FOUND: u32 = 0xC000_008A;
pub const STATUS_RESOURCE_NAME_NOT_FOUND: u32 = 0xC000_008B;
pub const STATUS_RESOURCE_LANG_NOT_FOUND: u32 = 0xC000_0204;
pub const STATUS_MESSAGE_NOT_FOUND: u32 = 0xC000_0109;

/// The optional header's data directory index of the resource directory.
const DIR_RESOURCE: u32 = 2;
/// An entry's high bit: its name is a string (Name), its target a subtable (OffsetToData).
const HIGH_BIT: u32 = 0x8000_0000;

/// US English (LANG_ENGLISH, SUBLANG_ENGLISH_US): the last language of the documented search, and
/// F2K's one locale's.
pub const LANG_ENGLISH_US: u16 = 0x0409;
/// LANG_NEUTRAL's sublanguages that stand for a default: SUBLANG_DEFAULT (the user's) and
/// SUBLANG_SYS_DEFAULT (the system's).
const SUBLANG_DEFAULT: u16 = 1;
const SUBLANG_SYS_DEFAULT: u16 = 2;

/// The languages a search may fall back on: the calling thread's, the user's default and the
/// system's default.
#[derive(Clone, Copy, Debug)]
pub struct Defaults {
    pub thread: u16,
    pub user: u16,
    pub system: u16,
}

impl Defaults {
    /// F2K's: its one locale, US English, for all three.
    pub const F2K: Defaults = Defaults {
        thread: LANG_ENGLISH_US,
        user: LANG_ENGLISH_US,
        system: LANG_ENGLISH_US,
    };
}

/// The languages a search for `language` tries, in order, and whether it then takes any language
/// the name has. The FormatMessage documentation's order for zero: the neutral language, the
/// thread's, the user's default, the system's default, US English, then any. LANG_NEUTRAL with
/// SUBLANG_DEFAULT is the user's default language, with SUBLANG_SYS_DEFAULT the system's (winnt.h);
/// any other language is that language only.
pub fn languages(language: u16, defaults: Defaults) -> ([u16; 5], usize, bool) {
    let mut list = [0u16; 5];
    let count = match language {
        0 => {
            list = [
                0,
                defaults.thread,
                defaults.user,
                defaults.system,
                LANG_ENGLISH_US,
            ];
            5
        }
        _ if language & 0x3FF == 0 && language >> 10 == SUBLANG_DEFAULT => {
            list[0] = defaults.user;
            1
        }
        _ if language & 0x3FF == 0 && language >> 10 == SUBLANG_SYS_DEFAULT => {
            list[0] = defaults.system;
            1
        }
        _ => {
            list[0] = language;
            1
        }
    };
    (list, count, language == 0)
}

/// A path element (ULONG_PTR): a numbered identifier, or the address of a NUL-terminated UTF-16
/// name.
fn is_numbered(element: u32) -> bool {
    element >> 16 == 0
}

/// The resource directory of the image mapped at `base`: its root table's address and the
/// directory's size; none for an image without one.
pub fn root<M: Memory>(memory: &M, base: u32) -> Option<(u32, u32)> {
    if memory.half(base) != 0x5A4D {
        return None; // "MZ"
    }
    let nt = base.wrapping_add(memory.word(base + 0x3C));
    if memory.word(nt) != 0x0000_4550 {
        return None; // "PE\0\0"
    }
    let optional = nt + 0x18;
    if memory.half(optional) != 0x010B || memory.word(optional + 0x5C) <= DIR_RESOURCE {
        return None; // not PE32, or no resource directory slot
    }
    let at = optional + 0x60 + 8 * DIR_RESOURCE;
    let (rva, size) = (memory.word(at), memory.word(at + 4));
    (rva != 0 && size != 0).then(|| (base.wrapping_add(rva), size))
}

/// The image's size (the optional header's SizeOfImage), for an image [`root`] read.
fn size_of_image<M: Memory>(memory: &M, base: u32) -> u32 {
    let nt = base.wrapping_add(memory.word(base + 0x3C));
    memory.word(nt + 0x18 + 0x38)
}

/// The entry of the table at `table` for the element `element`: its OffsetToData word (the high
/// bit set for a subtable). Named entries come first, then numbered ones; each run is searched in
/// full.
fn entry<M: Memory>(memory: &M, root: u32, table: u32, element: u32) -> Option<u32> {
    let named = u32::from(memory.half(table + 12));
    let numbered = u32::from(memory.half(table + 14));
    let entries = table + 16;
    if is_numbered(element) {
        (named..named + numbered)
            .map(|index| entries + 8 * index)
            .find(|&at| memory.word(at) == element)
            .map(|at| memory.word(at + 4))
    } else {
        (0..named)
            .map(|index| entries + 8 * index)
            .find(|&at| {
                let name = memory.word(at);
                name & HIGH_BIT != 0 && same_name(memory, root + (name & !HIGH_BIT), element)
            })
            .map(|at| memory.word(at + 4))
    }
}

/// Whether the IMAGE_RESOURCE_DIR_STRING_U at `string` (a length in units, then the units) is the
/// NUL-terminated name at `name`, unit for unit.
fn same_name<M: Memory>(memory: &M, string: u32, name: u32) -> bool {
    let length = u32::from(memory.half(string));
    (0..length).all(|index| memory.half(string + 2 + 2 * index) == memory.half(name + 2 * index))
        && memory.half(name + 2 * length) == 0
}

/// The first entry of the table at `table`, in its order: its OffsetToData word.
fn first_entry<M: Memory>(memory: &M, table: u32) -> Option<u32> {
    let count = u32::from(memory.half(table + 12)) + u32::from(memory.half(table + 14));
    (count != 0).then(|| memory.word(table + 16 + 4))
}

/// The status of an element a table does not hold, by its level: a type, a name, a language.
fn missing(level: usize) -> u32 {
    match level {
        0 => STATUS_RESOURCE_TYPE_NOT_FOUND,
        1 => STATUS_RESOURCE_NAME_NOT_FOUND,
        _ => STATUS_RESOURCE_LANG_NOT_FOUND,
    }
}

/// What a walk found: a table (IMAGE_RESOURCE_DIRECTORY) or a data entry
/// (IMAGE_RESOURCE_DATA_ENTRY), by address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    Table(u32),
    Data(u32),
}

/// The walk LdrFindResource_U and LdrFindResourceDirectory_U share: down the resource directory of
/// the image at `base` along `path` (the type, the name, the language), the third element searched
/// as [`languages`] orders it. STATUS_RESOURCE_DATA_NOT_FOUND for an image without resources, or a
/// data entry where the path goes on; the level's status for an element not found.
pub fn walk<M: Memory>(
    memory: &M,
    base: u32,
    path: &[u32],
    defaults: Defaults,
) -> Result<Found, u32> {
    let (root, _) = root(memory, base).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
    let mut found = Found::Table(root);
    for (level, &element) in path.iter().enumerate() {
        let Found::Table(table) = found else {
            return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
        };
        let target = if level == 2 && is_numbered(element) {
            let (list, count, any) = languages(element as u16, defaults);
            list[..count]
                .iter()
                .find_map(|&language| entry(memory, root, table, u32::from(language)))
                .or_else(|| any.then(|| first_entry(memory, table)).flatten())
        } else {
            entry(memory, root, table, element)
        };
        let target = target.ok_or(missing(level))?;
        let at = root + (target & !HIGH_BIT);
        found = if target & HIGH_BIT != 0 {
            Found::Table(at)
        } else {
            Found::Data(at)
        };
    }
    Ok(found)
}

/// LdrFindResource_U's work: the data entry `path` leads to (see [`walk`]); a table there is
/// STATUS_RESOURCE_DATA_NOT_FOUND.
pub fn find_data<M: Memory>(
    memory: &M,
    base: u32,
    path: &[u32],
    defaults: Defaults,
) -> Result<u32, u32> {
    match walk(memory, base, path, defaults)? {
        Found::Data(at) => Ok(at),
        Found::Table(_) => Err(STATUS_RESOURCE_DATA_NOT_FOUND),
    }
}

/// LdrFindResourceDirectory_U's work: the table `path` leads to (see [`walk`]; an empty path is the
/// root); a data entry there is STATUS_RESOURCE_DATA_NOT_FOUND.
pub fn find_table<M: Memory>(
    memory: &M,
    base: u32,
    path: &[u32],
    defaults: Defaults,
) -> Result<u32, u32> {
    match walk(memory, base, path, defaults)? {
        Found::Table(at) => Ok(at),
        Found::Data(_) => Err(STATUS_RESOURCE_DATA_NOT_FOUND),
    }
}

/// LdrAccessResource's work: the data's address and size, of the data entry at `entry` in the
/// image at `base`. STATUS_RESOURCE_DATA_NOT_FOUND for data that does not lie inside the image.
pub fn access<M: Memory>(memory: &M, base: u32, entry: u32) -> Result<(u32, u32), u32> {
    let (rva, size) = (memory.word(entry), memory.word(entry + 4));
    let inside = rva
        .checked_add(size)
        .is_some_and(|end| end <= size_of_image(memory, base));
    if !inside {
        return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
    }
    Ok((base.wrapping_add(rva), size))
}

/// The MESSAGE_RESOURCE_ENTRY for `id` in the MESSAGE_RESOURCE_DATA at `table` (`size` bytes): its
/// address; STATUS_MESSAGE_NOT_FOUND when no block holds the identifier (or a record's length would
/// leave the table).
pub fn message_entry<M: Memory>(memory: &M, table: u32, size: u32, id: u32) -> Result<u32, u32> {
    let end = table.wrapping_add(size);
    let blocks = memory.word(table);
    for block in 0..blocks.min(size / 12) {
        let at = table + 4 + 12 * block;
        let (low, high, offset) = (memory.word(at), memory.word(at + 4), memory.word(at + 8));
        if id < low || id > high {
            continue;
        }
        let mut entry = table.wrapping_add(offset);
        for _ in low..id {
            let length = u32::from(memory.half(entry));
            if length < 4 || entry.wrapping_add(length) > end {
                return Err(STATUS_MESSAGE_NOT_FOUND);
            }
            entry += length;
        }
        if entry.wrapping_add(4) > end {
            return Err(STATUS_MESSAGE_NOT_FOUND);
        }
        return Ok(entry);
    }
    Err(STATUS_MESSAGE_NOT_FOUND)
}

/// RtlFindMessage's work: the MESSAGE_RESOURCE_ENTRY of message `id` in the message table the image
/// at `base` carries as resource type `table_type` (RT_MESSAGETABLE), name 1, in `language` (see
/// [`languages`]). [`walk`]'s statuses for a table not found; STATUS_MESSAGE_NOT_FOUND for a table
/// without the identifier.
pub fn find_message<M: Memory>(
    memory: &M,
    base: u32,
    table_type: u32,
    language: u32,
    id: u32,
    defaults: Defaults,
) -> Result<u32, u32> {
    let path = [table_type, MESSAGE_TABLE_NAME, language & 0xFFFF];
    let data = find_data(memory, base, &path, defaults)?;
    let (table, size) = access(memory, base, data)?;
    message_entry(memory, table, size, id)
}

#[cfg(test)]
pub mod model {
    //! Message tables and resource directories, laid out as the tests' images carry them.

    /// A MESSAGE_RESOURCE_DATA of `messages` (identifier, text; ascending identifiers), its texts
    /// UTF-16 (`unicode`) or bytes, each NUL-terminated and padded to a dword: one block per run
    /// of consecutive identifiers.
    pub fn message_table(messages: &[(u32, &str)], unicode: bool) -> std::vec::Vec<u8> {
        let mut runs: std::vec::Vec<std::vec::Vec<(u32, &str)>> = std::vec::Vec::new();
        for &(id, text) in messages {
            match runs.last_mut() {
                Some(run) if run.last().unwrap().0 + 1 == id => run.push((id, text)),
                _ => runs.push(std::vec![(id, text)]),
            }
        }
        let mut entries = std::vec::Vec::new();
        let mut blocks = std::vec::Vec::new();
        let start = 4 + 12 * runs.len();
        for run in &runs {
            blocks.push((run[0].0, run.last().unwrap().0, start + entries.len()));
            for (_, text) in run {
                let mut bytes: std::vec::Vec<u8> = if unicode {
                    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
                } else {
                    text.as_bytes().to_vec()
                };
                bytes.extend_from_slice(if unicode { &[0, 0] } else { &[0] });
                while (bytes.len() + 4) % 4 != 0 {
                    bytes.push(0);
                }
                entries.extend_from_slice(&((bytes.len() + 4) as u16).to_le_bytes());
                entries.extend_from_slice(&u16::from(unicode).to_le_bytes());
                entries.extend_from_slice(&bytes);
            }
        }
        let mut table = (runs.len() as u32).to_le_bytes().to_vec();
        for (low, high, offset) in blocks {
            for value in [low, high, offset as u32] {
                table.extend_from_slice(&value.to_le_bytes());
            }
        }
        table.extend_from_slice(&entries);
        table
    }
}

#[cfg(test)]
mod tests {
    use super::model::message_table;
    use super::*;
    use crate::modules::model::{image, Space};

    const BASE: u32 = 0x7C4E_0000;
    /// Where the tests' images keep their resource directory, and its size.
    const RESOURCES: usize = 0x1000;
    const SIZE: usize = 0x1000;

    /// A table at `at` in `bytes` (relative to the directory) with `named` named and the rest
    /// numbered entries: (name or identifier, target offset, whether a subtable). A name is the
    /// offset of its IMAGE_RESOURCE_DIR_STRING_U.
    fn table(bytes: &mut [u8], at: usize, named: usize, entries: &[(u32, u32, bool)]) {
        bytes[at + 12..at + 14].copy_from_slice(&(named as u16).to_le_bytes());
        bytes[at + 14..at + 16].copy_from_slice(&((entries.len() - named) as u16).to_le_bytes());
        for (index, &(name, target, subtable)) in entries.iter().enumerate() {
            let entry = at + 16 + 8 * index;
            let name = if index < named { name | HIGH_BIT } else { name };
            let target = if subtable { target | HIGH_BIT } else { target };
            bytes[entry..entry + 4].copy_from_slice(&name.to_le_bytes());
            bytes[entry + 4..entry + 8].copy_from_slice(&target.to_le_bytes());
        }
    }

    fn put(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// An image at BASE whose resources are: a message table (type 11, name 1) in US English and in
    /// French (its texts marked as such), and type 6 holding a resource named "HELLO" in the
    /// neutral language.
    fn process() -> Space {
        let mut bytes = image(&[]);
        bytes.resize(RESOURCES + SIZE, 0);
        // SizeOfImage, and the resource directory's slot.
        put(&mut bytes, 0x58 + 0x38, (RESOURCES + SIZE) as u32);
        put(&mut bytes, 0x58 + 0x60 + 16, RESOURCES as u32);
        put(&mut bytes, 0x58 + 0x60 + 20, SIZE as u32);
        let r = &mut bytes[RESOURCES..];
        // The root: type 6 and type 11 (numbered).
        table(r, 0x00, 0, &[(6, 0x100, true), (11, 0x40, true)]);
        // Type 11: name 1. Name 1: French, then US English.
        table(r, 0x40, 0, &[(1, 0x60, true)]);
        table(r, 0x60, 0, &[(0x040C, 0x80, false), (0x0409, 0x90, false)]);
        let english = message_table(&[(2, "file\r\n"), (3, "path\r\n"), (5, "denied\r\n")], true);
        let french = message_table(&[(2, "fichier\r\n")], true);
        put(r, 0x80, (RESOURCES + 0x400) as u32);
        put(r, 0x84, french.len() as u32);
        put(r, 0x90, (RESOURCES + 0x200) as u32);
        put(r, 0x94, english.len() as u32);
        r[0x200..0x200 + english.len()].copy_from_slice(&english);
        r[0x400..0x400 + french.len()].copy_from_slice(&french);
        // Type 6: the name "HELLO" (its string at 0x140), neutral language.
        table(r, 0x100, 1, &[(0x140, 0x160, true)]);
        r[0x140..0x142].copy_from_slice(&5u16.to_le_bytes());
        for (index, unit) in "HELLO".encode_utf16().enumerate() {
            r[0x142 + 2 * index..0x144 + 2 * index].copy_from_slice(&unit.to_le_bytes());
        }
        table(r, 0x160, 0, &[(0, 0x180, false)]);
        put(r, 0x180, (RESOURCES + 0x600) as u32);
        put(r, 0x184, 4);
        Space(std::vec![
            (BASE, bytes),
            (0x0001_0000, name("HELLO")),
            (0x0002_0000, name("HELL"))
        ])
    }

    /// A NUL-terminated UTF-16 name.
    fn name(text: &str) -> std::vec::Vec<u8> {
        text.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// The text of the entry at `at`: its UTF-16 units to the first NUL.
    fn text(memory: &Space, at: u32) -> std::string::String {
        assert_eq!(memory.half(at + 2), MESSAGE_RESOURCE_UNICODE);
        let units: std::vec::Vec<u16> = (0..)
            .map(|index| memory.half(at + 4 + 2 * index))
            .take_while(|&unit| unit != 0)
            .collect();
        std::string::String::from_utf16(&units).unwrap()
    }

    /// The documented search order for language zero; the defaults LANG_NEUTRAL stands for; any
    /// other language alone.
    #[test]
    fn the_languages_a_search_tries() {
        let defaults = Defaults {
            thread: 0x0407,
            user: 0x040C,
            system: 0x0410,
        };
        assert_eq!(
            languages(0, defaults),
            ([0, 0x0407, 0x040C, 0x0410, 0x0409], 5, true)
        );
        assert_eq!(languages(0x0400, defaults).0[0], 0x040C);
        assert_eq!(languages(0x0400, defaults).1, 1);
        assert_eq!(languages(0x0800, defaults).0[0], 0x0410);
        assert_eq!(
            languages(0x040C, defaults),
            ([0x040C, 0, 0, 0, 0], 1, false)
        );
    }

    /// RtlFindMessage: the US English table for zero (US English is the documented search's last
    /// language before any), for MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT) (the user's) and for
    /// itself; French for French.
    #[test]
    fn messages_are_found_by_identifier_and_language() {
        let memory = process();
        let find = |language, id| find_message(&memory, BASE, 11, language, id, Defaults::F2K);
        for language in [0, 0x0400, 0x0409] {
            assert_eq!(text(&memory, find(language, 2).unwrap()), "file\r\n");
        }
        assert_eq!(text(&memory, find(0, 3).unwrap()), "path\r\n");
        assert_eq!(text(&memory, find(0, 5).unwrap()), "denied\r\n");
        assert_eq!(text(&memory, find(0x040C, 2).unwrap()), "fichier\r\n");
        assert_eq!(find(0, 4), Err(STATUS_MESSAGE_NOT_FOUND));
        assert_eq!(find(0, 0x0123_4567), Err(STATUS_MESSAGE_NOT_FOUND));
        assert_eq!(find(0x0407, 2), Err(STATUS_RESOURCE_LANG_NOT_FOUND));
        assert_eq!(
            find_message(&memory, BASE, 12, 0, 2, Defaults::F2K),
            Err(STATUS_RESOURCE_TYPE_NOT_FOUND)
        );
    }

    /// Language zero takes any language when the search's own find none.
    #[test]
    fn language_zero_falls_back_on_any() {
        let memory = process();
        let defaults = Defaults {
            thread: 0x0407,
            user: 0x0407,
            system: 0x0407,
        };
        // The neutral language leads the search: "HELLO" has only it.
        let hello = 0x0001_0000;
        assert!(find_data(&memory, BASE, &[6, hello, 0], defaults).is_ok());
        // With French first in the table, a search finding none of its languages takes French.
        let mut memory = memory;
        memory.0[0].1[RESOURCES + 0x60 + 16 + 8..RESOURCES + 0x60 + 16 + 12]
            .copy_from_slice(&0x0809u32.to_le_bytes());
        let entry = find_message(&memory, BASE, 11, 0, 2, defaults).unwrap();
        assert_eq!(text(&memory, entry), "fichier\r\n");
    }

    /// Names match exactly; each level's miss has its own status; the directory walk finds tables,
    /// the data walk data entries; LdrAccessResource hands the data's address and size.
    #[test]
    fn the_walk_reports_each_level() {
        let memory = process();
        let (hello, hell) = (0x0001_0000, 0x0002_0000);
        let entry = find_data(&memory, BASE, &[6, hello, 0], Defaults::F2K).unwrap();
        assert_eq!(
            access(&memory, BASE, entry),
            Ok((BASE + RESOURCES as u32 + 0x600, 4))
        );
        assert_eq!(
            find_data(&memory, BASE, &[6, hell, 0], Defaults::F2K),
            Err(STATUS_RESOURCE_NAME_NOT_FOUND)
        );
        assert_eq!(
            find_data(&memory, BASE, &[7], Defaults::F2K),
            Err(STATUS_RESOURCE_TYPE_NOT_FOUND)
        );
        assert_eq!(
            find_data(&memory, BASE, &[6, hello], Defaults::F2K),
            Err(STATUS_RESOURCE_DATA_NOT_FOUND),
            "a table is no data"
        );
        assert_eq!(
            find_table(&memory, BASE, &[], Defaults::F2K),
            Ok(BASE + RESOURCES as u32)
        );
        assert_eq!(
            find_table(&memory, BASE, &[11, 1], Defaults::F2K),
            Ok(BASE + RESOURCES as u32 + 0x60)
        );
        assert_eq!(
            find_table(&memory, BASE, &[11, 1, 0x0409], Defaults::F2K),
            Err(STATUS_RESOURCE_DATA_NOT_FOUND),
            "a data entry is no table"
        );
    }

    /// An image without a resource directory has no resources.
    #[test]
    fn an_image_without_resources() {
        let memory = Space(std::vec![(BASE, image(&[]))]);
        assert_eq!(
            find_message(&memory, BASE, 11, 0, 2, Defaults::F2K),
            Err(STATUS_RESOURCE_DATA_NOT_FOUND)
        );
    }

    /// A table's records are found by walking the lengths; a length that leaves the table stops the
    /// walk.
    #[test]
    fn message_records_are_walked_by_their_lengths() {
        let table = message_table(&[(10, "a"), (11, "bcdef"), (12, "g"), (20, "h")], false);
        let memory = Space(std::vec![(0x1000, table.clone())]);
        let size = table.len() as u32;
        let at = |id| message_entry(&memory, 0x1000, size, id);
        assert_eq!(memory.byte(at(12).unwrap() + 4), b'g');
        assert_eq!(memory.byte(at(20).unwrap() + 4), b'h');
        assert_eq!(memory.half(at(11).unwrap() + 2), 0, "an ANSI record");
        assert_eq!(at(13), Err(STATUS_MESSAGE_NOT_FOUND));
        let mut broken = table;
        let first = 4 + 24;
        broken[first..first + 2].copy_from_slice(&0u16.to_le_bytes());
        let memory = Space(std::vec![(0x1000, broken)]);
        assert_eq!(
            message_entry(&memory, 0x1000, size, 12),
            Err(STATUS_MESSAGE_NOT_FOUND)
        );
    }
}
