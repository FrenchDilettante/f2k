//! Path lookup: walk directories, entry by entry and cluster by cluster, from the root to a file.
//!
//! A directory is a cluster chain read as 32-byte records in order; the walk follows the chain
//! between clusters through the FAT reader and stops at the end record. `.` and `..` are resolved
//! by the walk itself — it remembers the directories it descended through — so the on-disk dot
//! records are never consulted. A broken chain or a record pointing outside the volume fails the
//! lookup as corrupt, never as a panic.

use super::dir::{walk, Listed};
use super::dirent::{Times, ATTR_DIRECTORY};
use super::path::{components, is_valid, Component};
use super::volume::Volume;
use crate::status::{
    NtStatus,
    STATUS_FILE_CORRUPT_ERROR,
    STATUS_NOT_A_DIRECTORY,
    STATUS_NO_SUCH_FILE,
    STATUS_OBJECT_NAME_INVALID,
};

/// How deep a path may descend: directories the walk remembers for `..`.
pub const MAX_DEPTH: usize = 32;

/// What a lookup found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct File {
    /// The first cluster (0 for an empty file).
    pub first_cluster: u32,
    /// The size in bytes (0 for a directory).
    pub size: u32,
    pub directory: bool,
    /// The attribute bits (the root's: a directory).
    pub attributes: u8,
    /// The timestamps as stored (the root has none).
    pub times: Times,
    /// The entry's identity: its directory's first cluster and its record index there. The root's
    /// is (0, 0).
    pub parent_cluster: u32,
    pub index: u32,
}

impl File {
    /// A file or directory with no attributes beyond the directory bit, no timestamps, and no
    /// identity (the tests' shorthand).
    pub const fn plain(first_cluster: u32, size: u32, directory: bool) -> File {
        File {
            first_cluster,
            size,
            directory,
            attributes: if directory { ATTR_DIRECTORY } else { 0 },
            times: Times {
                create_hundredths: 0,
                create_time: 0,
                create_date: 0,
                access_date: 0,
                write_time: 0,
                write_date: 0,
            },
            parent_cluster: 0,
            index: 0,
        }
    }

    /// The entry `listed` of the directory starting at `parent_cluster`.
    pub fn of(listed: &Listed, parent_cluster: u32) -> File {
        let entry = &listed.entry;
        File {
            first_cluster: entry.first_cluster,
            size: if entry.is_directory() { 0 } else { entry.size },
            directory: entry.is_directory(),
            attributes: entry.attributes,
            times: entry.times,
            parent_cluster,
            index: listed.index,
        }
    }
}

/// Why a lookup failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LookupError {
    /// The path is malformed: empty, an empty component, a component no name may be, or deeper
    /// than [`MAX_DEPTH`].
    Invalid,
    /// A component names no entry of its directory.
    NotFound,
    /// The path continues past a file.
    NotADirectory,
    /// A directory's chain or a record is broken.
    Corrupt,
    /// A device read failed.
    Device(NtStatus),
}

impl LookupError {
    /// The NT status the failure reports.
    pub fn status(&self) -> NtStatus {
        match *self {
            LookupError::Invalid => STATUS_OBJECT_NAME_INVALID,
            LookupError::NotFound => STATUS_NO_SUCH_FILE,
            LookupError::NotADirectory => STATUS_NOT_A_DIRECTORY,
            LookupError::Corrupt => STATUS_FILE_CORRUPT_ERROR,
            LookupError::Device(status) => status,
        }
    }
}

/// Find the entry answering to `name` (its long or its 8.3 name, any case) in the directory
/// starting at `cluster`, in the directory's own order; none when the directory has no such entry.
/// The dot records answer to nothing.
pub fn find(volume: &mut Volume, cluster: u32, name: &[u8]) -> Result<Option<Listed>, LookupError> {
    let mut found = None;
    walk(volume, cluster, |listed| {
        if !listed.dot && listed.matches(name) {
            found = Some(*listed);
            return false;
        }
        true
    })?;
    Ok(found)
}

/// The root directory's File.
pub fn root(volume: &Volume) -> File {
    File::plain(volume.layout().root_cluster, 0, true)
}

/// Look up a root-relative path (see [`super::path`]): the file or directory it names.
pub fn lookup(volume: &mut Volume, path: &[u8]) -> Result<File, LookupError> {
    lookup_with(volume, path, |_| {})
}

/// [`lookup`], calling `step` with the entry each name component matched, in order.
pub fn lookup_with(
    volume: &mut Volume,
    path: &[u8],
    mut step: impl FnMut(&Listed),
) -> Result<File, LookupError> {
    if !is_valid(path) {
        return Err(LookupError::Invalid);
    }
    let root = root(volume);
    // The directories above the current one, for `..`, by first cluster (a parent is a directory,
    // and `..` names it without its entry's details: the walk keeps the gate stack small).
    let mut parents = [0u32; MAX_DEPTH];
    let mut depth = 0;
    let mut current = root;
    for component in components(path) {
        if !current.directory {
            return Err(LookupError::NotADirectory);
        }
        match component {
            Component::Current => {}
            Component::Parent => {
                if depth > 0 {
                    depth -= 1;
                    current = File::plain(parents[depth], 0, true);
                }
            }
            Component::Name(name) => {
                let listed =
                    find(volume, current.first_cluster, name)?.ok_or(LookupError::NotFound)?;
                if depth == MAX_DEPTH {
                    return Err(LookupError::Invalid);
                }
                step(&listed);
                parents[depth] = current.first_cluster;
                depth += 1;
                current = File::of(&listed, current.first_cluster);
            }
        }
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::super::dirent::{ATTR_LONG_NAME, DELETED, ESCAPED_E5};
    use super::super::fixtures::{built_volume_with_root, record, Counting, Crafted};
    use super::*;

    const FILE: u8 = 0x20;
    const DIR: u8 = 0x10;

    fn mount(crafted: &Crafted) -> Volume {
        Volume::mount(crafted.device()).unwrap()
    }

    /// The real root directory: HELLO.EXE at cluster 3 with 28672 bytes — found by any case — the
    /// BOOT directory, and the kernel by its short name and by its long name; the label is never
    /// matched.
    #[test]
    fn the_real_root_directory() {
        let mut volume = Volume::mount(built_volume_with_root()).unwrap();
        let shape =
            |file: Result<File, LookupError>| file.map(|f| (f.first_cluster, f.size, f.directory));
        assert_eq!(
            shape(lookup(&mut volume, b"HELLO.EXE")),
            Ok((3, 28_672, false))
        );
        assert_eq!(
            shape(lookup(&mut volume, b"hello.exe")),
            Ok((3, 28_672, false))
        );
        assert_eq!(shape(lookup(&mut volume, b"boot")), Ok((59, 0, true)));
        assert!(matches!(lookup(&mut volume, b"F2K-KE~1"), Ok(file) if file.first_cluster == 61));
        assert_eq!(
            lookup(&mut volume, b"F2K"),
            Err(LookupError::NotFound),
            "the label"
        );
        assert!(
            matches!(lookup(&mut volume, b"f2k-kernel"), Ok(file) if file.first_cluster == 61),
            "the long name"
        );
        assert_eq!(
            lookup(&mut volume, b"MISSING.TXT"),
            Err(LookupError::NotFound)
        );
    }

    /// One lookup in the real root reads the root's one sector, and nothing else: the walk stops
    /// at the matching record.
    #[test]
    fn a_root_lookup_reads_one_sector() {
        let device = Counting::over(built_volume_with_root());
        let mut volume = Volume::mount(device).unwrap();
        let before = device.reads();
        lookup(&mut volume, b"HELLO.EXE").unwrap();
        assert_eq!(device.reads() - before, 1);
    }

    /// Names are found in the directory's own order, past deleted, long-name, label, and dot
    /// records; the end record stops the walk, so an entry after it is never seen.
    #[test]
    fn the_walk_skips_and_stops() {
        let mut deleted = record(b"TARGET  TXT", FILE, 9, 1);
        deleted[0] = DELETED;
        let mut crafted = Crafted::new(1, 8);
        crafted.directory(
            2,
            &[
                record(b"VOLUME     ", 0x08, 0, 0),
                record(b".          ", DIR, 2, 0),
                record(b"Ax\x00y\x00z\x00\x00\x00\x00\x00", ATTR_LONG_NAME, 0, 0),
                deleted,
                record(b"TARGET  TXT", FILE, 4, 10),
                record(b"TARGET  TXT", FILE, 5, 20),
                [0u8; 32],
                record(b"LATE    TXT", FILE, 6, 30),
            ],
        );
        let mut volume = mount(&crafted);
        assert_eq!(
            lookup(&mut volume, b"target.txt").map(|f| f.first_cluster),
            Ok(4),
            "the first live match, not the deleted one or the second"
        );
        assert_eq!(lookup(&mut volume, b"LATE.TXT"), Err(LookupError::NotFound));
        assert_eq!(lookup(&mut volume, b"VOLUME"), Err(LookupError::NotFound));
    }

    /// An entry whose stored name begins with the 0x05 escape is an entry, its real first byte
    /// 0xE5: in code page 437, where short names are stored, that is a sigma, which no code page
    /// 1252 name spells — the 1252 byte 0xE5 (a ring a) is another character, and does not find it.
    /// An entry stored with 437's capital ring A (0x8F) is what it finds.
    #[test]
    fn the_escape_stands_for_a_real_first_byte() {
        let mut escaped = record(b"XNAME   TXT", FILE, 4, 1);
        escaped[0] = ESCAPED_E5;
        let mut crafted = Crafted::new(1, 4);
        crafted.directory(2, &[escaped, record(b"\x8FNAME   TXT", FILE, 5, 1)]);
        let mut volume = mount(&crafted);
        let mut first = None;
        walk(&mut volume, 2, |listed| {
            first = Some(listed.entry.name[0]);
            false
        })
        .unwrap();
        assert_eq!(first, Some(0xE5));
        assert_eq!(
            lookup(&mut volume, b"\xE5name.txt").map(|f| f.first_cluster),
            Ok(5)
        );
    }

    /// A directory spanning two clusters: the walk follows the chain from the first, full one
    /// into the second.
    #[test]
    fn a_directory_spans_two_clusters() {
        let filler: Vec<[u8; 32]> = (0..16u8)
            .map(|index| {
                let mut name = *b"FILL0      ";
                name[4] = b'A' + index;
                record(&name, FILE, 10, 1)
            })
            .collect();
        let mut crafted = Crafted::new(1, 8);
        crafted
            .chain(&[2, 5])
            .directory(2, &filler)
            .directory(5, &[record(b"SECOND  TXT", FILE, 7, 1)]);
        let mut volume = mount(&crafted);
        assert_eq!(
            lookup(&mut volume, b"SECOND.TXT").map(|f| f.first_cluster),
            Ok(7)
        );
        assert_eq!(
            lookup(&mut volume, b"FILLA").map(|f| f.first_cluster),
            Ok(10)
        );
        assert_eq!(lookup(&mut volume, b"NOPE"), Err(LookupError::NotFound));
    }

    /// A volume of 4-sector clusters walks every sector of a directory cluster.
    #[test]
    fn a_multi_sector_cluster_is_walked_whole() {
        let mut records: Vec<[u8; 32]> = (0..40u8)
            .map(|index| {
                let mut name = *b"N00        ";
                name[1] = b'0' + index / 10;
                name[2] = b'0' + index % 10;
                record(&name, FILE, 9, 1)
            })
            .collect();
        records.push(record(b"DEEP    BIN", FILE, 12, 99));
        let mut crafted = Crafted::new(4, 12);
        crafted.directory(2, &records);
        let mut volume = mount(&crafted);
        assert_eq!(lookup(&mut volume, b"deep.bin").map(|f| f.size), Ok(99));
    }

    /// `.` stays, `..` climbs — from the walk's own memory, so a subdirectory's on-disk `..`
    /// (which points at cluster 0 for the root) is never followed — and the root's `..` is the
    /// root.
    #[test]
    fn dot_components_resolve_in_the_walk() {
        let mut crafted = Crafted::new(1, 8);
        crafted
            .directory(
                2,
                &[
                    record(b"SUB        ", DIR, 4, 0),
                    record(b"TOP     TXT", FILE, 6, 5),
                ],
            )
            .directory(
                4,
                &[
                    record(b".          ", DIR, 4, 0),
                    record(b"..         ", DIR, 0, 0),
                    record(b"INNER   TXT", FILE, 7, 3),
                ],
            );
        let mut volume = mount(&crafted);
        let top = |volume: &mut Volume, path: &[u8]| lookup(volume, path).map(|f| f.first_cluster);
        assert_eq!(top(&mut volume, b"sub\\inner.txt"), Ok(7));
        assert_eq!(top(&mut volume, b"sub\\..\\top.txt"), Ok(6));
        assert_eq!(top(&mut volume, b".\\sub\\.\\inner.txt"), Ok(7));
        assert_eq!(top(&mut volume, b"..\\..\\top.txt"), Ok(6));
        assert_eq!(top(&mut volume, b"sub\\..\\..\\sub\\inner.txt"), Ok(7));
        assert_eq!(lookup(&mut volume, b"."), Ok(File::plain(2, 0, true)));
        assert_eq!(
            top(&mut volume, b"sub\\inner.txt\\.."),
            Err(LookupError::NotADirectory)
        );
    }

    /// The three refusals, each distinct: malformed input, a missing component, and a path that
    /// continues past a file.
    #[test]
    fn the_refusals_are_distinct() {
        let mut crafted = Crafted::new(1, 8);
        crafted
            .directory(
                2,
                &[
                    record(b"SUB        ", DIR, 4, 0),
                    record(b"FILE    TXT", FILE, 6, 5),
                ],
            )
            .directory(4, &[record(b"INNER   TXT", FILE, 7, 3)]);
        let mut volume = mount(&crafted);
        for bad in [
            &b""[..],
            b"\\FILE.TXT",
            b"SUB\\",
            b"SUB\\\\INNER.TXT",
            b"WHAT?.TXT",
        ] {
            assert_eq!(lookup(&mut volume, bad), Err(LookupError::Invalid));
        }
        assert_eq!(
            lookup(&mut volume, b"long-name.txt"),
            Err(LookupError::NotFound)
        );
        assert_eq!(lookup(&mut volume, b"NOPE.TXT"), Err(LookupError::NotFound));
        assert_eq!(
            lookup(&mut volume, b"NOPE\\INNER.TXT"),
            Err(LookupError::NotFound)
        );
        assert_eq!(
            lookup(&mut volume, b"SUB\\NOPE.TXT"),
            Err(LookupError::NotFound)
        );
        assert_eq!(
            lookup(&mut volume, b"FILE.TXT\\INNER.TXT"),
            Err(LookupError::NotADirectory)
        );

        assert_eq!(LookupError::Invalid.status(), STATUS_OBJECT_NAME_INVALID);
        assert_eq!(LookupError::NotFound.status(), STATUS_NO_SUCH_FILE);
        assert_eq!(LookupError::NotADirectory.status(), STATUS_NOT_A_DIRECTORY);
        assert_eq!(LookupError::Corrupt.status(), STATUS_FILE_CORRUPT_ERROR);
    }

    /// A directory whose chain breaks (a free entry mid-chain), loops, or names a cluster outside
    /// the volume is corrupt.
    #[test]
    fn a_broken_directory_is_corrupt() {
        let full: Vec<[u8; 32]> = (0..16)
            .map(|_| record(b"FILL       ", FILE, 9, 1))
            .collect();

        let mut free_link = Crafted::new(1, 8);
        free_link.directory(2, &full).fat(2, 0);
        let mut volume = mount(&free_link);
        assert_eq!(lookup(&mut volume, b"X"), Err(LookupError::Corrupt));

        let mut looping = Crafted::new(1, 8);
        looping.directory(2, &full).fat(2, 2);
        let mut volume = mount(&looping);
        assert_eq!(lookup(&mut volume, b"X"), Err(LookupError::Corrupt));

        let mut outside = Crafted::new(1, 8);
        outside.directory(2, &[record(b"SUB        ", DIR, 1, 0)]);
        let mut volume = mount(&outside);
        assert_eq!(lookup(&mut volume, b"SUB\\X"), Err(LookupError::Corrupt));
    }

    #[test]
    fn a_path_deeper_than_the_walk_remembers_is_invalid() {
        let mut crafted = Crafted::new(1, 4);
        crafted.directory(2, &[record(b"LOOP       ", DIR, 2, 0)]);
        let mut volume = mount(&crafted);
        let deep: Vec<u8> = (0..=MAX_DEPTH)
            .flat_map(|_| b"LOOP\\".iter().copied())
            .chain(*b"LOOP")
            .collect();
        assert_eq!(lookup(&mut volume, &deep), Err(LookupError::Invalid));
        let shallow: Vec<u8> = (0..MAX_DEPTH - 1)
            .flat_map(|_| b"LOOP\\".iter().copied())
            .chain(*b"LOOP")
            .collect();
        assert!(lookup(&mut volume, &shallow).is_ok());
    }
}
