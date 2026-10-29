//! The information classes the file services answer and take, and their structures (ntifs.h, NT
//! 5.0, x86; see [`rtl::nt::info`]): the per-file ones (NtQueryInformationFile,
//! NtSetInformationFile, NtQueryAttributesFile, NtQueryFullAttributesFile), the directory listings'
//! (NtQueryDirectoryFile) and the volume's (NtQueryVolumeInformationFile).
//! Times are FILETIMEs (the FAT stamps are local time, UTC here); FAT keeps no change time (zero);
//! a file's allocation is its size in whole clusters; its index number names its entry (its
//! directory's first cluster, then its record there), as GetFileInformationByHandle's file index
//! reads it.

use rtl::nt::info::{
    FileAccessInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileBasicInformation,
    FileBothDirInformation,
    FileDirectoryInformation,
    FileDispositionInformation,
    FileEaInformation,
    FileEndOfFileInformation,
    FileFsAttributeInformation,
    FileFsDeviceInformation,
    FileFsFullSizeInformation,
    FileFsSizeInformation,
    FileFsVolumeInformation,
    FileFullDirInformation,
    FileInternalInformation,
    FileModeInformation,
    FileNamesInformation,
    FileNetworkOpenInformation,
    FilePositionInformation,
    FileRenameInformation,
    FileStandardInformation,
    VariableSize,
};
use rtl::pod::Pod;

use crate::fs::fat32::lookup::File;
use crate::fs::file::rights;
use crate::fs::io::{attributes, file_times};

info_class! {
    /// The per-file classes a query answers (FILE_INFORMATION_CLASS).
    pub enum QueryClass {
        Basic = 4,
        Standard = 5,
        Internal = 6,
        Ea = 7,
        Access = 8,
        Position = 14,
        Mode = 16,
        Alignment = 17,
        All = 18,
        NetworkOpen = 34,
    }
}

impl QueryClass {
    /// The smallest buffer the query takes: the class's structure, as the I/O manager's length
    /// table has it.
    pub fn min_size(self) -> usize {
        match self {
            QueryClass::Basic => size_of::<FileBasicInformation>(),
            QueryClass::Standard => size_of::<FileStandardInformation>(),
            QueryClass::Internal => size_of::<FileInternalInformation>(),
            QueryClass::Ea => size_of::<FileEaInformation>(),
            QueryClass::Access => size_of::<FileAccessInformation>(),
            QueryClass::Position => size_of::<FilePositionInformation>(),
            QueryClass::Mode => size_of::<FileModeInformation>(),
            QueryClass::Alignment => size_of::<FileAlignmentInformation>(),
            QueryClass::All => size_of::<FileAllInformation>(),
            QueryClass::NetworkOpen => size_of::<FileNetworkOpenInformation>(),
        }
    }

    /// The rights the query needs: FILE_READ_ATTRIBUTES for the times and the attributes, none for
    /// the rest.
    pub fn rights(self) -> u32 {
        match self {
            QueryClass::Basic | QueryClass::All | QueryClass::NetworkOpen => {
                rights::FILE_READ_ATTRIBUTES
            }
            _ => 0,
        }
    }
}

info_class! {
    /// The per-file classes a set takes (FILE_INFORMATION_CLASS).
    pub enum SetClass {
        Basic = 4,
        Rename = 10,
        Disposition = 13,
        Position = 14,
        Allocation = 19,
        EndOfFile = 20,
    }
}

impl SetClass {
    /// The smallest buffer the set takes: the class's structure.
    pub fn min_size(self) -> usize {
        match self {
            SetClass::Basic => size_of::<FileBasicInformation>(),
            SetClass::Rename => size_of::<FileRenameInformation>(),
            SetClass::Disposition => size_of::<FileDispositionInformation>(),
            SetClass::Position => size_of::<FilePositionInformation>(),
            SetClass::Allocation => size_of::<FileAllocationInformation>(),
            SetClass::EndOfFile => size_of::<FileEndOfFileInformation>(),
        }
    }

    /// The rights the set needs: FILE_WRITE_ATTRIBUTES for the times and the attributes, DELETE
    /// for a rename or a delete, FILE_WRITE_DATA for the size, none for the position.
    pub fn rights(self) -> u32 {
        match self {
            SetClass::Basic => rights::FILE_WRITE_ATTRIBUTES,
            SetClass::Rename | SetClass::Disposition => rights::DELETE,
            SetClass::Allocation | SetClass::EndOfFile => rights::FILE_WRITE_DATA,
            SetClass::Position => 0,
        }
    }
}

info_class! {
    /// The classes a directory listing answers in (FILE_INFORMATION_CLASS).
    pub enum ListingClass {
        Directory = 1,
        FullDirectory = 2,
        BothDirectory = 3,
        Names = 12,
    }
}

impl ListingClass {
    /// A record's fixed part (where its name starts): what a listing's buffer must hold at least.
    pub fn fixed_size(self) -> usize {
        match self {
            ListingClass::Directory => FileDirectoryInformation::FIXED_SIZE,
            ListingClass::FullDirectory => FileFullDirInformation::FIXED_SIZE,
            ListingClass::BothDirectory => FileBothDirInformation::FIXED_SIZE,
            ListingClass::Names => FileNamesInformation::FIXED_SIZE,
        }
    }
}

info_class! {
    /// The volume classes (FS_INFORMATION_CLASS).
    pub enum VolumeClass {
        Volume = 1,
        Size = 3,
        Device = 4,
        Attribute = 5,
        FullSize = 7,
    }
}

impl VolumeClass {
    /// The smallest buffer the query takes: the class's structure.
    pub fn min_size(self) -> usize {
        match self {
            VolumeClass::Volume => size_of::<FileFsVolumeInformation>(),
            VolumeClass::Size => size_of::<FileFsSizeInformation>(),
            VolumeClass::Device => size_of::<FileFsDeviceInformation>(),
            VolumeClass::Attribute => size_of::<FileFsAttributeInformation>(),
            VolumeClass::FullSize => size_of::<FileFsFullSizeInformation>(),
        }
    }
}

/// FILE_DEVICE_DISK: the volume's device type.
pub const FILE_DEVICE_DISK: u32 = 7;
/// FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK: what FAT32 reports.
pub const FAT32_ATTRIBUTES: u32 = 0x2 | 0x4;
/// The longest component FAT32 stores.
pub const FAT32_MAX_COMPONENT: u32 = 255;
/// The volume's sector size.
const BYTES_PER_SECTOR: u32 = 512;

/// A structure's bytes at the start of `out` (which holds them): their length.
fn put<T: Pod>(out: &mut [u8], value: &T) -> usize {
    let bytes = value.as_bytes();
    out[..bytes.len()].copy_from_slice(bytes);
    bytes.len()
}

/// A variable-size structure's fixed part, then its name's units, into `out` (which holds the
/// fixed part at least; the name's length is the structure's to give): the length written, or Err
/// with it when the name did not fit (as much of it as fits written).
fn put_named<T: VariableSize>(out: &mut [u8], value: &T, name: &[u16]) -> Result<usize, usize> {
    let fixed = value.fixed_part();
    out[..fixed.len()].copy_from_slice(fixed);
    let (slots, _) = out[fixed.len()..].as_chunks_mut::<2>();
    let units = &name[..name.len().min(slots.len())];
    for (slot, unit) in slots.iter_mut().zip(units) {
        *slot = unit.to_le_bytes();
    }
    let written = fixed.len() + 2 * units.len();
    if units.len() == name.len() {
        Ok(written)
    } else {
        Err(written)
    }
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
pub fn basic(file: &File) -> FileBasicInformation {
    let [creation_time, last_access_time, last_write_time] = file_times(file);
    FileBasicInformation {
        creation_time,
        last_access_time,
        last_write_time,
        file_attributes: attributes(file.attributes),
        ..Default::default()
    }
}

/// FILE_STANDARD_INFORMATION: the allocation, the end of file, one link, the pending delete, and
/// whether it is a directory.
pub fn standard(file: &File, open: &Open) -> FileStandardInformation {
    FileStandardInformation {
        allocation_size: open.allocation,
        end_of_file: file.size as u64,
        number_of_links: 1,
        delete_pending: u8::from(open.delete_pending),
        directory: u8::from(file.directory),
        ..Default::default()
    }
}

/// FILE_INTERNAL_INFORMATION: the index number, the entry's directory then its record.
pub fn internal(file: &File) -> FileInternalInformation {
    FileInternalInformation {
        index_number: (u64::from(file.parent_cluster) << 32) | u64::from(file.index),
    }
}

/// FILE_NETWORK_OPEN_INFORMATION: the times, the allocation and end of file, the attributes.
pub fn network_open(file: &File, allocation: u64) -> FileNetworkOpenInformation {
    let [creation_time, last_access_time, last_write_time] = file_times(file);
    FileNetworkOpenInformation {
        creation_time,
        last_access_time,
        last_write_time,
        allocation_size: allocation,
        end_of_file: file.size as u64,
        file_attributes: attributes(file.attributes),
        ..Default::default()
    }
}

/// FILE_ALL_INFORMATION: basic, standard, internal, EA (none), access, position, mode, alignment
/// (bytes), and the name (F2K keeps no open's name: an empty one).
pub fn all(file: &File, open: &Open) -> FileAllInformation {
    FileAllInformation {
        basic: basic(file),
        standard: standard(file, open),
        internal: internal(file),
        access: FileAccessInformation {
            access_flags: open.granted,
        },
        position: FilePositionInformation {
            current_byte_offset: open.position,
        },
        mode: FileModeInformation { mode: open.mode },
        ..Default::default()
    }
}

/// A per-file class's answer for a query, into `out` (at least the class's size): the bytes
/// written.
pub fn query(class: QueryClass, file: &File, open: &Open, out: &mut [u8]) -> usize {
    match class {
        QueryClass::Basic => put(out, &basic(file)),
        QueryClass::Standard => put(out, &standard(file, open)),
        QueryClass::Internal => put(out, &internal(file)),
        QueryClass::Ea => put(out, &FileEaInformation::default()),
        QueryClass::Access => put(
            out,
            &FileAccessInformation {
                access_flags: open.granted,
            },
        ),
        QueryClass::Position => put(
            out,
            &FilePositionInformation {
                current_byte_offset: open.position,
            },
        ),
        QueryClass::Mode => put(out, &FileModeInformation { mode: open.mode }),
        QueryClass::Alignment => put(out, &FileAlignmentInformation::default()),
        QueryClass::All => put(out, &all(file, open)),
        QueryClass::NetworkOpen => put(out, &network_open(file, open.allocation)),
    }
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

/// Write `entry` as a listing class's record into `out` (NextEntryOffset left zero): its length,
/// or, when its name does not fit, Err with the length of the record holding what does (the fixed
/// part must fit: the caller checks).
pub fn directory_entry(class: ListingClass, entry: &Entry, out: &mut [u8]) -> Result<usize, usize> {
    let [creation_time, last_access_time, last_write_time] = file_times(&entry.file);
    let file_index = entry.index;
    let end_of_file = entry.file.size as u64;
    let allocation_size = entry.allocation;
    let file_attributes = attributes(entry.file.attributes);
    let file_name_length = 2 * entry.name.len() as u32;
    match class {
        ListingClass::Directory => {
            let record = FileDirectoryInformation {
                file_index,
                creation_time,
                last_access_time,
                last_write_time,
                end_of_file,
                allocation_size,
                file_attributes,
                file_name_length,
                ..Default::default()
            };
            put_named(out, &record, entry.name)
        }
        ListingClass::FullDirectory => {
            let record = FileFullDirInformation {
                file_index,
                creation_time,
                last_access_time,
                last_write_time,
                end_of_file,
                allocation_size,
                file_attributes,
                file_name_length,
                ..Default::default()
            };
            put_named(out, &record, entry.name)
        }
        ListingClass::BothDirectory => {
            let mut short_name = [0u16; 12];
            for (slot, &unit) in short_name.iter_mut().zip(entry.short) {
                *slot = unit;
            }
            let record = FileBothDirInformation {
                file_index,
                creation_time,
                last_access_time,
                last_write_time,
                end_of_file,
                allocation_size,
                file_attributes,
                file_name_length,
                short_name_length: (2 * entry.short.len()) as u8,
                short_name,
                ..Default::default()
            };
            put_named(out, &record, entry.name)
        }
        ListingClass::Names => {
            let record = FileNamesInformation {
                file_index,
                file_name_length,
                ..Default::default()
            };
            put_named(out, &record, entry.name)
        }
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

/// A volume class's answer into `out` (at least its fixed size): the length written, or Err with
/// it when a name did not fit (STATUS_BUFFER_OVERFLOW, as much as fits written).
pub fn volume_query(class: VolumeClass, volume: &Volume, out: &mut [u8]) -> Result<usize, usize> {
    match class {
        VolumeClass::Volume => {
            let mut units = [0u16; 11];
            let label = &mut units[..volume.label().len()];
            for (unit, &byte) in label.iter_mut().zip(volume.label()) {
                *unit = rtl::cp1252::MB_TO_WC[byte as usize];
            }
            let info = FileFsVolumeInformation {
                volume_serial_number: volume.serial,
                volume_label_length: 2 * label.len() as u32,
                ..Default::default()
            };
            // A label shorter than the structure's tail still answers the whole structure.
            put_named(out, &info, label).map(|length| length.max(size_of_val(&info)))
        }
        VolumeClass::Size => Ok(put(
            out,
            &FileFsSizeInformation {
                total_allocation_units: volume.clusters as u64,
                available_allocation_units: volume.free_clusters as u64,
                sectors_per_allocation_unit: volume.sectors_per_cluster,
                bytes_per_sector: BYTES_PER_SECTOR,
            },
        )),
        VolumeClass::FullSize => Ok(put(
            out,
            &FileFsFullSizeInformation {
                total_allocation_units: volume.clusters as u64,
                caller_available_allocation_units: volume.free_clusters as u64,
                actual_available_allocation_units: volume.free_clusters as u64,
                sectors_per_allocation_unit: volume.sectors_per_cluster,
                bytes_per_sector: BYTES_PER_SECTOR,
            },
        )),
        VolumeClass::Device => Ok(put(
            out,
            &FileFsDeviceInformation {
                device_type: FILE_DEVICE_DISK,
                characteristics: 0,
            },
        )),
        VolumeClass::Attribute => {
            let name = b"FAT32".map(u16::from);
            let info = FileFsAttributeInformation {
                file_system_attributes: FAT32_ATTRIBUTES,
                maximum_component_name_length: FAT32_MAX_COMPONENT,
                file_system_name_length: 2 * name.len() as u32,
                ..Default::default()
            };
            put_named(out, &info, &name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::fat32::dirent::Times;
    use crate::status::STATUS_INVALID_INFO_CLASS;

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
        assert_eq!(
            basic.last_write_time,
            file_times(&file)[2],
            "the last write"
        );
        assert_eq!(u32_at(basic.as_bytes(), 32), 0x21);
        let standard = standard(&file, &open);
        let bytes = standard.as_bytes();
        assert_eq!(
            (u64_at(bytes, 0), u64_at(bytes, 8), u32_at(bytes, 16)),
            (4096, 1000, 1)
        );
        assert_eq!((bytes[20], bytes[21]), (1, 0));
        let all = all(&file, &open);
        let bytes = all.as_bytes();
        assert_eq!(u64_at(bytes, 48), 1000, "standard's end of file");
        assert_eq!(u64_at(bytes, 64), (5 << 32) | 7, "the index number");
        assert_eq!(
            (u32_at(bytes, 76), u64_at(bytes, 80), u32_at(bytes, 88)),
            (0x12_0089, 77, 0x20)
        );
        assert_eq!(u32_at(bytes, 96), 0, "no name");
        let network = network_open(&file, open.allocation);
        let bytes = network.as_bytes();
        assert_eq!(
            (u64_at(bytes, 32), u64_at(bytes, 40), u32_at(bytes, 48)),
            (4096, 1000, 0x21)
        );
        let mut out = [0u8; 8];
        assert_eq!(query(QueryClass::Position, &file, &open, &mut out), 8);
        assert_eq!(u64::from_le_bytes(out), 77);
        assert_eq!(
            QueryClass::try_from(9),
            Err(STATUS_INVALID_INFO_CLASS),
            "the name is not kept"
        );
        assert_eq!(
            (
                QueryClass::try_from(18).map(QueryClass::min_size),
                SetClass::try_from(13).map(SetClass::min_size)
            ),
            (Ok(104), Ok(1))
        );
        assert_eq!(SetClass::try_from(10).map(SetClass::min_size), Ok(16));
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
        let length = directory_entry(ListingClass::BothDirectory, &entry, &mut out).unwrap();
        assert_eq!(length, 94 + 36);
        assert_eq!((u32_at(&out, 0), u32_at(&out, 4)), (0, 3));
        assert_eq!(
            (u64_at(&out, 40), u32_at(&out, 56), u32_at(&out, 60)),
            (1000, 0x21, 36)
        );
        assert_eq!((out[68], out[69]), (24, 0));
        assert_eq!(&out[70..72], &[b'L', 0]);
        assert_eq!(&out[94..96], &[b'L', 0]);
        assert_eq!(
            directory_entry(ListingClass::BothDirectory, &entry, &mut out[..100]),
            Err(100)
        );
        assert_eq!(
            directory_entry(ListingClass::Names, &entry, &mut out).unwrap(),
            12 + 36
        );
        assert_eq!(
            ListingClass::try_from(2).map(ListingClass::fixed_size),
            Ok(68)
        );
        assert_eq!(
            ListingClass::try_from(1).map(ListingClass::fixed_size),
            Ok(64)
        );
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
        assert_eq!(volume_query(VolumeClass::Volume, &volume, &mut out), Ok(24));
        assert_eq!((u32_at(&out, 8), u32_at(&out, 12)), (0x1234_5678, 6));
        assert_eq!(&out[18..24], &[b'F', 0, b'2', 0, b'K', 0]);
        assert_eq!(volume_query(VolumeClass::Size, &volume, &mut out), Ok(24));
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
            volume_query(VolumeClass::FullSize, &volume, &mut out),
            Ok(32)
        );
        assert_eq!((u32_at(&out, 24), u32_at(&out, 28)), (8, 512));
        assert_eq!(volume_query(VolumeClass::Device, &volume, &mut out), Ok(8));
        assert_eq!(u32_at(&out, 0), FILE_DEVICE_DISK);
        assert_eq!(
            volume_query(VolumeClass::Attribute, &volume, &mut out),
            Ok(22)
        );
        assert_eq!(
            (u32_at(&out, 0), u32_at(&out, 4), u32_at(&out, 8)),
            (6, 255, 10)
        );
        assert_eq!(
            volume_query(VolumeClass::Attribute, &volume, &mut out[..16]),
            Err(16)
        );
        assert_eq!(
            VolumeClass::try_from(2).map(VolumeClass::min_size),
            Err(STATUS_INVALID_INFO_CLASS)
        );
        let unnamed = Volume {
            label: *b"NO NAME    ",
            ..volume
        };
        assert_eq!(unnamed.label(), b"");
        assert_eq!(
            volume_query(VolumeClass::Volume, &unnamed, &mut out),
            Ok(24)
        );
    }
}
