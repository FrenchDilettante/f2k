//! The information classes the file services answer and take, as their structures lay them out
//! (ntifs.h, NT 5.0, x86): the per-file ones (NtQueryInformationFile, NtSetInformationFile,
//! NtQueryAttributesFile, NtQueryFullAttributesFile), the directory listings'
//! (NtQueryDirectoryFile) and the volume's (NtQueryVolumeInformationFile).
//! Times are FILETIMEs (the FAT stamps are local time, UTC here); FAT keeps no change time (zero);
//! a file's allocation is its size in whole clusters; its index number names its entry (its
//! directory's first cluster, then its record there), as GetFileInformationByHandle's file index
//! reads it.

use crate::fs::fat32::lookup::File;
use crate::fs::io::{attributes, file_times};

/// The per-file classes (FILE_INFORMATION_CLASS).
pub const FILE_DIRECTORY_INFORMATION: u32 = 1;
pub const FILE_FULL_DIRECTORY_INFORMATION: u32 = 2;
pub const FILE_BOTH_DIRECTORY_INFORMATION: u32 = 3;
pub const FILE_BASIC_INFORMATION: u32 = 4;
pub const FILE_STANDARD_INFORMATION: u32 = 5;
pub const FILE_INTERNAL_INFORMATION: u32 = 6;
pub const FILE_EA_INFORMATION: u32 = 7;
pub const FILE_ACCESS_INFORMATION: u32 = 8;
pub const FILE_RENAME_INFORMATION: u32 = 10;
pub const FILE_NAMES_INFORMATION: u32 = 12;
pub const FILE_DISPOSITION_INFORMATION: u32 = 13;
pub const FILE_POSITION_INFORMATION: u32 = 14;
pub const FILE_MODE_INFORMATION: u32 = 16;
pub const FILE_ALIGNMENT_INFORMATION: u32 = 17;
pub const FILE_ALL_INFORMATION: u32 = 18;
pub const FILE_ALLOCATION_INFORMATION: u32 = 19;
pub const FILE_END_OF_FILE_INFORMATION: u32 = 20;
pub const FILE_NETWORK_OPEN_INFORMATION: u32 = 34;

/// The volume classes (FS_INFORMATION_CLASS).
pub const FILE_FS_VOLUME_INFORMATION: u32 = 1;
pub const FILE_FS_SIZE_INFORMATION: u32 = 3;
pub const FILE_FS_DEVICE_INFORMATION: u32 = 4;
pub const FILE_FS_ATTRIBUTE_INFORMATION: u32 = 5;
pub const FILE_FS_FULL_SIZE_INFORMATION: u32 = 7;

/// The structures' sizes (their fixed parts, for the variable ones: what a call must hand over at
/// least, as the I/O manager's length tables have them).
pub const BASIC_SIZE: usize = 40;
pub const STANDARD_SIZE: usize = 24;
pub const NETWORK_OPEN_SIZE: usize = 56;
pub const ALL_SIZE: usize = 104;
pub const RENAME_SIZE: usize = 16;
pub const FS_VOLUME_SIZE: usize = 24;
pub const FS_SIZE_SIZE: usize = 24;
pub const FS_DEVICE_SIZE: usize = 8;
pub const FS_ATTRIBUTE_SIZE: usize = 16;
pub const FS_FULL_SIZE_SIZE: usize = 32;

/// FILE_DEVICE_DISK: the volume's device type.
pub const FILE_DEVICE_DISK: u32 = 7;
/// FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK: what FAT32 reports.
pub const FAT32_ATTRIBUTES: u32 = 0x2 | 0x4;
/// The longest component FAT32 stores.
pub const FAT32_MAX_COMPONENT: u32 = 255;

fn put32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// What the per-file classes report of an open file beyond its entry.
#[derive(Clone, Copy, Default)]
pub struct Open {
    /// Its allocation in bytes (its size in whole clusters).
    pub allocation: u64,
    pub delete_pending: bool,
    pub position: u64,
    /// The rights granted (FileAccessInformation).
    pub granted: u32,
    /// The open's mode (FileModeInformation): its synchronous-I/O option.
    pub mode: u32,
}

/// A file's allocation: its size rounded up to whole clusters of `cluster` bytes.
pub fn allocation(file: &File, cluster: u32) -> u64 {
    if file.directory {
        return 0;
    }
    (file.size as u64).div_ceil(cluster as u64) * cluster as u64
}

/// FILE_BASIC_INFORMATION: the times and the attributes.
pub fn basic(file: &File) -> [u8; BASIC_SIZE] {
    let mut out = [0u8; BASIC_SIZE];
    for (index, time) in file_times(file).iter().enumerate() {
        put64(&mut out, 8 * index, *time);
    }
    put32(&mut out, 32, attributes(file.attributes));
    out
}

/// FILE_STANDARD_INFORMATION: the allocation, the end of file, one link, the pending delete, and
/// whether it is a directory.
pub fn standard(file: &File, open: &Open) -> [u8; STANDARD_SIZE] {
    let mut out = [0u8; STANDARD_SIZE];
    put64(&mut out, 0, open.allocation);
    put64(&mut out, 8, file.size as u64);
    put32(&mut out, 16, 1);
    out[20] = u8::from(open.delete_pending);
    out[21] = u8::from(file.directory);
    out
}

/// FILE_INTERNAL_INFORMATION's index number: the entry's directory, then its record.
pub fn index_number(file: &File) -> u64 {
    (u64::from(file.parent_cluster) << 32) | u64::from(file.index)
}

/// FILE_NETWORK_OPEN_INFORMATION: the times, the allocation and end of file, the attributes.
pub fn network_open(file: &File, allocation: u64) -> [u8; NETWORK_OPEN_SIZE] {
    let mut out = [0u8; NETWORK_OPEN_SIZE];
    for (index, time) in file_times(file).iter().enumerate() {
        put64(&mut out, 8 * index, *time);
    }
    put64(&mut out, 32, allocation);
    put64(&mut out, 40, file.size as u64);
    put32(&mut out, 48, attributes(file.attributes));
    out
}

/// FILE_ALL_INFORMATION: basic, standard, internal, EA (none), access, position, mode, alignment
/// (bytes), and the name (F2K keeps no open's name: an empty one).
pub fn all(file: &File, open: &Open) -> [u8; ALL_SIZE] {
    let mut out = [0u8; ALL_SIZE];
    out[..BASIC_SIZE].copy_from_slice(&basic(file));
    out[40..64].copy_from_slice(&standard(file, open));
    put64(&mut out, 64, index_number(file));
    put32(&mut out, 76, open.granted);
    put64(&mut out, 80, open.position);
    put32(&mut out, 88, open.mode);
    out
}

/// A per-file class's answer for a query, into `out` (its length checked by the caller): the bytes
/// written; none for a class not answered.
pub fn query(class: u32, file: &File, open: &Open, out: &mut [u8]) -> Option<usize> {
    let answer: &[u8] = match class {
        FILE_BASIC_INFORMATION => &basic(file),
        FILE_STANDARD_INFORMATION => &standard(file, open),
        FILE_INTERNAL_INFORMATION => &index_number(file).to_le_bytes(),
        FILE_EA_INFORMATION | FILE_ALIGNMENT_INFORMATION => &[0; 4],
        FILE_ACCESS_INFORMATION => &open.granted.to_le_bytes(),
        FILE_POSITION_INFORMATION => &open.position.to_le_bytes(),
        FILE_MODE_INFORMATION => &open.mode.to_le_bytes(),
        FILE_ALL_INFORMATION => &all(file, open),
        FILE_NETWORK_OPEN_INFORMATION => &network_open(file, open.allocation),
        _ => return None,
    };
    out[..answer.len()].copy_from_slice(answer);
    Some(answer.len())
}

/// The smallest buffer a query of `class` takes (none: a class not answered).
pub fn query_size(class: u32) -> Option<usize> {
    Some(match class {
        FILE_BASIC_INFORMATION => BASIC_SIZE,
        FILE_STANDARD_INFORMATION => STANDARD_SIZE,
        FILE_INTERNAL_INFORMATION | FILE_POSITION_INFORMATION => 8,
        FILE_EA_INFORMATION
        | FILE_ACCESS_INFORMATION
        | FILE_MODE_INFORMATION
        | FILE_ALIGNMENT_INFORMATION => 4,
        FILE_ALL_INFORMATION => ALL_SIZE,
        FILE_NETWORK_OPEN_INFORMATION => NETWORK_OPEN_SIZE,
        _ => return None,
    })
}

/// The smallest buffer a set of `class` takes (none: a class not taken).
pub fn set_size(class: u32) -> Option<usize> {
    Some(match class {
        FILE_BASIC_INFORMATION => BASIC_SIZE,
        FILE_RENAME_INFORMATION => RENAME_SIZE,
        FILE_DISPOSITION_INFORMATION => 1,
        FILE_POSITION_INFORMATION | FILE_ALLOCATION_INFORMATION | FILE_END_OF_FILE_INFORMATION => 8,
        _ => return None,
    })
}

// --- Directory listings --------------------------------------------------------------------------

/// One entry a listing reports.
pub struct Entry<'a> {
    /// Its record index in its directory (the entry's FileIndex).
    pub index: u32,
    pub file: File,
    pub allocation: u64,
    /// The name a listing shows, and the 8.3 name beside a long one (empty without one).
    pub name: &'a [u16],
    pub short: &'a [u16],
}

/// Where a listing class's name starts: its fixed part's size. None for a class not listed.
pub fn entry_name_offset(class: u32) -> Option<usize> {
    Some(match class {
        FILE_DIRECTORY_INFORMATION => 64,
        FILE_FULL_DIRECTORY_INFORMATION => 68,
        FILE_BOTH_DIRECTORY_INFORMATION => 94,
        FILE_NAMES_INFORMATION => 12,
        _ => return None,
    })
}

/// Write `entry` as a listing class's record into `out` (NextEntryOffset left zero): its length,
/// or, when its name does not fit, Err with the length of the record holding what does (the fixed
/// part must fit: the caller checks).
pub fn directory_entry(class: u32, entry: &Entry, out: &mut [u8]) -> Result<usize, usize> {
    let offset = entry_name_offset(class).expect("a listing class");
    out[..offset].fill(0);
    put32(out, 4, entry.index);
    if class == FILE_NAMES_INFORMATION {
        put32(out, 8, 2 * entry.name.len() as u32);
    } else {
        for (index, time) in file_times(&entry.file).iter().enumerate() {
            put64(out, 8 + 8 * index, *time);
        }
        put64(out, 40, entry.file.size as u64);
        put64(out, 48, entry.allocation);
        put32(out, 56, attributes(entry.file.attributes));
        put32(out, 60, 2 * entry.name.len() as u32);
        if class == FILE_BOTH_DIRECTORY_INFORMATION {
            out[68] = (2 * entry.short.len()) as u8;
            for (index, &unit) in entry.short.iter().take(12).enumerate() {
                out[70 + 2 * index..72 + 2 * index].copy_from_slice(&unit.to_le_bytes());
            }
        }
    }
    let room = (out.len() - offset) / 2;
    let fits = entry.name.len() <= room;
    for (index, &unit) in entry.name.iter().take(room).enumerate() {
        out[offset + 2 * index..offset + 2 * index + 2].copy_from_slice(&unit.to_le_bytes());
    }
    let length = offset + 2 * entry.name.len().min(room);
    if fits {
        Ok(length)
    } else {
        Err(length)
    }
}

// --- The volume ----------------------------------------------------------------------------------

/// The volume's facts the volume classes report.
#[derive(Clone, Copy)]
pub struct Volume {
    pub serial: u32,
    /// The label as the boot sector stores it (space-padded; "NO NAME" for none).
    pub label: [u8; 11],
    pub sectors_per_cluster: u32,
    pub clusters: u32,
    pub free_clusters: u32,
}

impl Volume {
    /// The label as reported: its trailing spaces gone, none for "NO NAME".
    pub fn label(&self) -> &[u8] {
        if &self.label == b"NO NAME    " {
            return &[];
        }
        &self.label[..self
            .label
            .iter()
            .rposition(|&byte| byte != b' ')
            .map_or(0, |at| at + 1)]
    }
}

/// The smallest buffer a volume query of `class` takes (none: a class not answered).
pub fn volume_query_size(class: u32) -> Option<usize> {
    Some(match class {
        FILE_FS_VOLUME_INFORMATION => FS_VOLUME_SIZE,
        FILE_FS_SIZE_INFORMATION => FS_SIZE_SIZE,
        FILE_FS_DEVICE_INFORMATION => FS_DEVICE_SIZE,
        FILE_FS_ATTRIBUTE_INFORMATION => FS_ATTRIBUTE_SIZE,
        FILE_FS_FULL_SIZE_INFORMATION => FS_FULL_SIZE_SIZE,
        _ => return None,
    })
}

/// A name's units into a structure at `at`, its length in bytes at `length_at`: the structure's
/// length, or Err with it when the name did not fit (as much as fits written).
fn put_name(
    out: &mut [u8],
    at: usize,
    length_at: usize,
    name: impl Iterator<Item = u16>,
    count: usize,
) -> Result<usize, usize> {
    put32(out, length_at, 2 * count as u32);
    let room = (out.len() - at) / 2;
    for (index, unit) in name.take(room).enumerate() {
        out[at + 2 * index..at + 2 * index + 2].copy_from_slice(&unit.to_le_bytes());
    }
    let written = at + 2 * count.min(room);
    if count <= room {
        Ok(written)
    } else {
        Err(written)
    }
}

/// A volume class's answer into `out` (at least its fixed size): the length written, or Err with
/// it when a name did not fit (STATUS_BUFFER_OVERFLOW, as much as fits written).
pub fn volume_query(class: u32, volume: &Volume, out: &mut [u8]) -> Result<usize, usize> {
    match class {
        FILE_FS_VOLUME_INFORMATION => {
            out[..18].fill(0);
            put32(out, 8, volume.serial);
            let label = volume.label();
            let units = label
                .iter()
                .map(|&byte| rtl::cp1252::MB_TO_WC[byte as usize]);
            put_name(out, 18, 12, units, label.len()).map(|length| length.max(FS_VOLUME_SIZE))
        }
        FILE_FS_SIZE_INFORMATION | FILE_FS_FULL_SIZE_INFORMATION => {
            put64(out, 0, volume.clusters as u64);
            put64(out, 8, volume.free_clusters as u64);
            let mut at = 16;
            if class == FILE_FS_FULL_SIZE_INFORMATION {
                put64(out, 16, volume.free_clusters as u64);
                at = 24;
            }
            put32(out, at, volume.sectors_per_cluster);
            put32(out, at + 4, 512);
            Ok(at + 8)
        }
        FILE_FS_DEVICE_INFORMATION => {
            put32(out, 0, FILE_DEVICE_DISK);
            put32(out, 4, 0);
            Ok(FS_DEVICE_SIZE)
        }
        FILE_FS_ATTRIBUTE_INFORMATION => {
            put32(out, 0, FAT32_ATTRIBUTES);
            put32(out, 4, FAT32_MAX_COMPONENT);
            put_name(out, 12, 8, b"FAT32".iter().map(|&byte| u16::from(byte)), 5)
        }
        _ => unreachable!("the caller checks the class"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::fat32::dirent::Times;

    fn file() -> File {
        let mut file = File::plain(9, 1000, false);
        file.attributes = 0x21;
        file.times = Times {
            write_date: (21 << 9) | (2 << 5) | 3,
            write_time: (4 << 11) | (5 << 5) | 3,
            ..Times::default()
        };
        file.parent_cluster = 5;
        file.index = 7;
        file
    }

    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn u64_at(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    /// The per-file classes' layouts, as kernel32 reads them.
    #[test]
    fn the_per_file_structures() {
        let file = file();
        let open = Open {
            allocation: allocation(&file, 4096),
            delete_pending: true,
            position: 77,
            granted: 0x12_0089,
            mode: 0x20,
        };
        assert_eq!(open.allocation, 4096);
        let basic = basic(&file);
        assert_eq!(u64_at(&basic, 16), file_times(&file)[2], "the last write");
        assert_eq!(u32_at(&basic, 32), 0x21);
        let standard = standard(&file, &open);
        assert_eq!(
            (
                u64_at(&standard, 0),
                u64_at(&standard, 8),
                u32_at(&standard, 16)
            ),
            (4096, 1000, 1)
        );
        assert_eq!((standard[20], standard[21]), (1, 0));
        let all = all(&file, &open);
        assert_eq!(u64_at(&all, 48), 1000, "standard's end of file");
        assert_eq!(u64_at(&all, 64), (5 << 32) | 7, "the index number");
        assert_eq!(
            (u32_at(&all, 76), u64_at(&all, 80), u32_at(&all, 88)),
            (0x12_0089, 77, 0x20)
        );
        assert_eq!(u32_at(&all, 96), 0, "no name");
        let network = network_open(&file, open.allocation);
        assert_eq!(
            (
                u64_at(&network, 32),
                u64_at(&network, 40),
                u32_at(&network, 48)
            ),
            (4096, 1000, 0x21)
        );
        let mut out = [0u8; 8];
        assert_eq!(
            query(FILE_POSITION_INFORMATION, &file, &open, &mut out),
            Some(8)
        );
        assert_eq!(u64::from_le_bytes(out), 77);
        assert_eq!(
            query(9, &file, &open, &mut out),
            None,
            "the name is not kept"
        );
        assert_eq!(
            (
                query_size(FILE_ALL_INFORMATION),
                set_size(FILE_DISPOSITION_INFORMATION)
            ),
            (Some(ALL_SIZE), Some(1))
        );
        assert_eq!(allocation(&File::plain(9, 0, true), 4096), 0);
    }

    /// A listing record: FileBothDirectoryInformation's fixed part, its 8.3 name, its name; a name
    /// that does not fit comes back cut.
    #[test]
    fn the_listing_records() {
        let name: std::vec::Vec<u16> = "Long File Name.txt".encode_utf16().collect();
        let short: std::vec::Vec<u16> = "LONGFI~1.TXT".encode_utf16().collect();
        let entry = Entry {
            index: 3,
            file: file(),
            allocation: 4096,
            name: &name,
            short: &short,
        };
        let mut out = [0xCCu8; 200];
        let length = directory_entry(FILE_BOTH_DIRECTORY_INFORMATION, &entry, &mut out).unwrap();
        assert_eq!(length, 94 + 36);
        assert_eq!((u32_at(&out, 0), u32_at(&out, 4)), (0, 3));
        assert_eq!(
            (u64_at(&out, 40), u32_at(&out, 56), u32_at(&out, 60)),
            (1000, 0x21, 36)
        );
        assert_eq!(out[68], 24);
        assert_eq!(&out[70..72], &[b'L', 0]);
        assert_eq!(&out[94..96], &[b'L', 0]);
        assert_eq!(
            directory_entry(FILE_BOTH_DIRECTORY_INFORMATION, &entry, &mut out[..100]),
            Err(100)
        );
        assert_eq!(
            directory_entry(FILE_NAMES_INFORMATION, &entry, &mut out).unwrap(),
            12 + 36
        );
        assert_eq!(entry_name_offset(FILE_FULL_DIRECTORY_INFORMATION), Some(68));
    }

    /// The volume classes, the label trimmed and a name that does not fit cut.
    #[test]
    fn the_volume_structures() {
        let volume = Volume {
            serial: 0x1234_5678,
            label: *b"F2K        ",
            sectors_per_cluster: 8,
            clusters: 1000,
            free_clusters: 600,
        };
        let mut out = [0u8; 64];
        assert_eq!(
            volume_query(FILE_FS_VOLUME_INFORMATION, &volume, &mut out),
            Ok(24)
        );
        assert_eq!((u32_at(&out, 8), u32_at(&out, 12)), (0x1234_5678, 6));
        assert_eq!(
            volume_query(FILE_FS_SIZE_INFORMATION, &volume, &mut out),
            Ok(24)
        );
        assert_eq!(
            (
                u64_at(&out, 0),
                u64_at(&out, 8),
                u32_at(&out, 16),
                u32_at(&out, 20)
            ),
            (1000, 600, 8, 512)
        );
        assert_eq!(
            volume_query(FILE_FS_FULL_SIZE_INFORMATION, &volume, &mut out),
            Ok(32)
        );
        assert_eq!((u32_at(&out, 24), u32_at(&out, 28)), (8, 512));
        assert_eq!(
            volume_query(FILE_FS_DEVICE_INFORMATION, &volume, &mut out),
            Ok(8)
        );
        assert_eq!(u32_at(&out, 0), FILE_DEVICE_DISK);
        assert_eq!(
            volume_query(FILE_FS_ATTRIBUTE_INFORMATION, &volume, &mut out),
            Ok(22)
        );
        assert_eq!(
            (u32_at(&out, 0), u32_at(&out, 4), u32_at(&out, 8)),
            (6, 255, 10)
        );
        assert_eq!(
            volume_query(FILE_FS_ATTRIBUTE_INFORMATION, &volume, &mut out[..16]),
            Err(16)
        );
        let unnamed = Volume {
            label: *b"NO NAME    ",
            ..volume
        };
        assert_eq!(unnamed.label(), b"");
    }
}
