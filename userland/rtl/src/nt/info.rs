//! The structures the query and set services answer and take, as NT 5.0's headers declare them on
//! x86 (ntifs.h, ntddk.h, ntexapi.h, winnt.h), one definition for the kernel that fills them and
//! the DLLs that read them: the per-file information classes (FILE_BASIC_INFORMATION and the others
//! FileAllInformation gathers, FILE_NETWORK_OPEN_INFORMATION, and the ones a set takes), the
//! directory listings' records, the volume classes (FILE_FS_*), the process and thread classes
//! (PROCESS_BASIC_INFORMATION, VM_COUNTERS, PROCESS_PRIORITY_CLASS, THREAD_BASIC_INFORMATION), the
//! system classes (SYSTEM_*, RTL_TIME_ZONE_INFORMATION), MEMORY_BASIC_INFORMATION, and the key and
//! value replies (KEY_*_INFORMATION, KEY_VALUE_*_INFORMATION).
//!
//! Every pointer-sized field is a `u32` (a 32-bit process's), every LARGE_INTEGER a `u64` (a time
//! or a size, never negative here), every BOOLEAN a `u8`. A structure that ends in a
//! variable-length array declares that array's first element, as the headers do, and implements
//! [`VariableSize`]: its fixed part is what precedes the array. The padding the headers' natural
//! alignment puts in a structure is a field of its own here (`padding`, `tail`), so every structure
//! is [`Pod`] and lays out alike on every target, whatever a `u64`'s alignment there: the asserts
//! below hold on the kernel's, the DLLs' and the host's.

use core::mem::{offset_of, size_of};

use super::ClientId;
use crate::pod::Pod;
use crate::time::TimeFields;

/// A structure ending in a variable-length array (a name, a class, data), declared with that
/// array's first element: its fixed part, the bytes before the array, is what a buffer must hold at
/// least and what the array follows.
pub trait VariableSize: Pod {
    /// The fixed part's size: where the array starts.
    const FIXED_SIZE: usize;

    /// The fixed part's bytes.
    fn fixed_part(&self) -> &[u8] {
        &self.as_bytes()[..Self::FIXED_SIZE]
    }
}

// --- The per-file classes (FILE_INFORMATION_CLASS) -----------------------------------------------

/// FILE_BASIC_INFORMATION: the four times (FILETIMEs) and the attributes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileBasicInformation {
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub file_attributes: u32,
    pub padding: u32,
}

/// FILE_STANDARD_INFORMATION: the allocation and the end of file, the links, and two BOOLEANs: a
/// delete pending, a directory.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileStandardInformation {
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub number_of_links: u32,
    pub delete_pending: u8,
    pub directory: u8,
    pub padding: [u8; 2],
}

/// FILE_INTERNAL_INFORMATION: the file's index number.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileInternalInformation {
    pub index_number: u64,
}

/// FILE_EA_INFORMATION: the extended attributes' size.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileEaInformation {
    pub ea_size: u32,
}

/// FILE_ACCESS_INFORMATION: the rights the open was granted.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileAccessInformation {
    pub access_flags: u32,
}

/// FILE_POSITION_INFORMATION: the open's current byte offset (query and set).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FilePositionInformation {
    pub current_byte_offset: u64,
}

/// FILE_MODE_INFORMATION: the open's mode (its FILE_SYNCHRONOUS_IO_* option).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileModeInformation {
    pub mode: u32,
}

/// FILE_ALIGNMENT_INFORMATION: the device's buffer alignment requirement.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileAlignmentInformation {
    pub alignment_requirement: u32,
}

/// FILE_NAME_INFORMATION: a name's length in bytes, then its units.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileNameInformation {
    pub file_name_length: u32,
    pub file_name: [u16; 1],
    pub padding: u16,
}

/// FILE_ALL_INFORMATION: the per-file classes in one, the name last.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileAllInformation {
    pub basic: FileBasicInformation,
    pub standard: FileStandardInformation,
    pub internal: FileInternalInformation,
    pub ea: FileEaInformation,
    pub access: FileAccessInformation,
    pub position: FilePositionInformation,
    pub mode: FileModeInformation,
    pub alignment: FileAlignmentInformation,
    pub name: FileNameInformation,
}

/// FILE_NETWORK_OPEN_INFORMATION: the times, the allocation and the end of file, the attributes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileNetworkOpenInformation {
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32,
    pub padding: u32,
}

/// FILE_RENAME_INFORMATION (a set): whether an existing target is replaced (a BOOLEAN), the
/// directory the name is relative to (a handle; zero for none), and the name's length in bytes,
/// then its units.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileRenameInformation {
    pub replace_if_exists: u8,
    pub padding: [u8; 3],
    pub root_directory: u32,
    pub file_name_length: u32,
    pub file_name: [u16; 1],
    pub tail: u16,
}

/// FILE_DISPOSITION_INFORMATION (a set): whether the file is deleted with its last handle (a
/// BOOLEAN).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileDispositionInformation {
    pub delete_file: u8,
}

/// FILE_ALLOCATION_INFORMATION (a set): the allocation asked for.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileAllocationInformation {
    pub allocation_size: u64,
}

/// FILE_END_OF_FILE_INFORMATION (a set): the new end of file.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileEndOfFileInformation {
    pub end_of_file: u64,
}

// --- The directory listings' records -------------------------------------------------------------

/// FILE_DIRECTORY_INFORMATION: a listed entry's record — the next record's offset (zero for the
/// last), the entry's index, its times, end of file, allocation and attributes, and its name.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileDirectoryInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub file_name_length: u32,
    pub file_name: [u16; 1],
    pub padding: [u16; 3],
}

/// FILE_FULL_DIR_INFORMATION: FILE_DIRECTORY_INFORMATION's fields and the extended attributes'
/// size, then the name.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileFullDirInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub file_name_length: u32,
    pub ea_size: u32,
    pub file_name: [u16; 1],
    pub padding: u16,
}

/// FILE_BOTH_DIR_INFORMATION: FILE_FULL_DIR_INFORMATION's fields and the 8.3 name beside the long
/// one (its length in bytes, a CCHAR, and its twelve units), then the name.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileBothDirInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub file_name_length: u32,
    pub ea_size: u32,
    pub short_name_length: u8,
    pub padding: u8,
    pub short_name: [u16; 12],
    pub file_name: [u16; 1],
}

/// FILE_NAMES_INFORMATION: the next record's offset, the entry's index, and its name.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileNamesInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub file_name_length: u32,
    pub file_name: [u16; 1],
    pub padding: u16,
}

// --- The volume classes (FS_INFORMATION_CLASS) ---------------------------------------------------

/// FILE_FS_VOLUME_INFORMATION: the volume's creation time, serial number, whether it supports
/// objects (a BOOLEAN), and its label.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileFsVolumeInformation {
    pub volume_creation_time: u64,
    pub volume_serial_number: u32,
    pub volume_label_length: u32,
    pub supports_objects: u8,
    pub padding: u8,
    pub volume_label: [u16; 1],
    pub tail: [u16; 2],
}

/// FILE_FS_SIZE_INFORMATION: the volume's clusters, the free ones, and their geometry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileFsSizeInformation {
    pub total_allocation_units: u64,
    pub available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

/// FILE_FS_DEVICE_INFORMATION: the device's type (FILE_DEVICE_*) and characteristics.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileFsDeviceInformation {
    pub device_type: u32,
    pub characteristics: u32,
}

/// FILE_FS_ATTRIBUTE_INFORMATION: the file system's flags (FILE_CASE_PRESERVED_NAMES and the
/// others), its longest component, and its name.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileFsAttributeInformation {
    pub file_system_attributes: u32,
    pub maximum_component_name_length: u32,
    pub file_system_name_length: u32,
    pub file_system_name: [u16; 1],
    pub padding: u16,
}

/// FILE_FS_FULL_SIZE_INFORMATION: the volume's clusters, the free ones the caller may use and all
/// the free ones, and their geometry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileFsFullSizeInformation {
    pub total_allocation_units: u64,
    pub caller_available_allocation_units: u64,
    pub actual_available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

// --- Processes and threads (PROCESSINFOCLASS, THREADINFOCLASS) -----------------------------------

/// PROCESS_BASIC_INFORMATION: a process's exit status (STATUS_PENDING, kernel32's STILL_ACTIVE,
/// until it ends), its PEB, its affinity, its base priority, its client id and its creator's.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessBasicInformation {
    pub exit_status: u32,
    pub peb_base_address: u32,
    pub affinity_mask: u32,
    pub base_priority: i32,
    pub unique_process_id: u32,
    pub inherited_from_unique_process_id: u32,
}

/// VM_COUNTERS: a process's virtual size, page faults, working set, pool and paging-file use, each
/// with its peak.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VmCounters {
    pub peak_virtual_size: u32,
    pub virtual_size: u32,
    pub page_fault_count: u32,
    pub peak_working_set_size: u32,
    pub working_set_size: u32,
    pub quota_peak_paged_pool_usage: u32,
    pub quota_paged_pool_usage: u32,
    pub quota_peak_non_paged_pool_usage: u32,
    pub quota_non_paged_pool_usage: u32,
    pub pagefile_usage: u32,
    pub peak_pagefile_usage: u32,
}

/// PROCESS_PRIORITY_CLASS: whether the process is in the foreground (a BOOLEAN), and its class
/// (PROCESS_PRIORITY_CLASS_*).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessPriorityClass {
    pub foreground: u8,
    pub priority_class: u8,
}

/// THREAD_BASIC_INFORMATION: a thread's exit status (STATUS_PENDING while it lives), its TEB, its
/// client id, its affinity, its current priority and its base priority's increment over its
/// process's.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ThreadBasicInformation {
    pub exit_status: u32,
    pub teb_base_address: u32,
    pub client_id: ClientId<u32>,
    pub affinity_mask: u32,
    pub priority: i32,
    pub base_priority: i32,
}

// --- The system classes (SYSTEM_INFORMATION_CLASS) -----------------------------------------------

/// SYSTEM_BASIC_INFORMATION: the clock's resolution, the page size, the physical pages and their
/// numbers' range, the allocation granularity, the application range, and the processors (their
/// mask, and their count: a CCHAR).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemBasicInformation {
    pub reserved: u32,
    pub timer_resolution: u32,
    pub page_size: u32,
    pub number_of_physical_pages: u32,
    pub lowest_physical_page_number: u32,
    pub highest_physical_page_number: u32,
    pub allocation_granularity: u32,
    pub minimum_user_mode_address: u32,
    pub maximum_user_mode_address: u32,
    pub active_processors_affinity_mask: u32,
    pub number_of_processors: u8,
    pub padding: [u8; 3],
}

/// SYSTEM_PROCESSOR_INFORMATION: the processor's architecture (PROCESSOR_ARCHITECTURE_*), level
/// and revision, and its feature bits.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemProcessorInformation {
    pub processor_architecture: u16,
    pub processor_level: u16,
    pub processor_revision: u16,
    pub reserved: u16,
    pub processor_feature_bits: u32,
}

/// SYSTEM_PERFORMANCE_INFORMATION: the system's counters. Its head is named — the idle time, the
/// I/O transfers and operations, and the memory manager's page counts — and the rest (the page
/// faults, the cache's, the pools' and the system calls' counters) is one array.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemPerformanceInformation {
    pub idle_process_time: u64,
    pub io_read_transfer_count: u64,
    pub io_write_transfer_count: u64,
    pub io_other_transfer_count: u64,
    pub io_read_operation_count: u32,
    pub io_write_operation_count: u32,
    pub io_other_operation_count: u32,
    pub available_pages: u32,
    pub committed_pages: u32,
    pub commit_limit: u32,
    pub peak_commitment: u32,
    /// PageFaultCount and every counter after it.
    pub counters: [u32; 63],
}

/// RTL_TIME_ZONE_INFORMATION (TIME_ZONE_INFORMATION's layout, its dates TIME_FIELDS): the bias in
/// minutes, and the standard and daylight-saving names, start dates and biases.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RtlTimeZoneInformation {
    pub bias: i32,
    pub standard_name: [u16; 32],
    pub standard_start: TimeFields,
    pub standard_bias: i32,
    pub daylight_name: [u16; 32],
    pub daylight_start: TimeFields,
    pub daylight_bias: i32,
}

// --- Memory (MEMORY_INFORMATION_CLASS) -----------------------------------------------------------

/// MEMORY_BASIC_INFORMATION: a run of pages alike — its base, its allocation's base and first
/// protection, its size, its state (MEM_COMMIT, MEM_RESERVE, MEM_FREE), its protection, and its
/// type (MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryBasicInformation {
    pub base_address: u32,
    pub allocation_base: u32,
    pub allocation_protect: u32,
    pub region_size: u32,
    pub state: u32,
    pub protect: u32,
    pub kind: u32,
}

// --- The registry's replies (KEY_INFORMATION_CLASS, KEY_VALUE_INFORMATION_CLASS) -----------------

/// KEY_BASIC_INFORMATION: a key's last write, its title index (unused), and its name.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyBasicInformation {
    pub last_write_time: u64,
    pub title_index: u32,
    pub name_length: u32,
    pub name: [u16; 1],
    pub padding: [u16; 3],
}

/// KEY_NODE_INFORMATION: a key's last write, its title index, where its class is (from the
/// structure's start) and its length, and its name; the class follows the name.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyNodeInformation {
    pub last_write_time: u64,
    pub title_index: u32,
    pub class_offset: u32,
    pub class_length: u32,
    pub name_length: u32,
    pub name: [u16; 1],
    pub padding: [u16; 3],
}

/// KEY_FULL_INFORMATION: a key's last write, its title index, where its class is and its length,
/// its subkeys and values with their longest names, classes and data; then the class.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyFullInformation {
    pub last_write_time: u64,
    pub title_index: u32,
    pub class_offset: u32,
    pub class_length: u32,
    pub sub_keys: u32,
    pub max_name_len: u32,
    pub max_class_len: u32,
    pub values: u32,
    pub max_value_name_len: u32,
    pub max_value_data_len: u32,
    pub class: [u16; 1],
    pub padding: u16,
}

/// KEY_VALUE_BASIC_INFORMATION: a value's title index (unused), its type (REG_*), and its name.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyValueBasicInformation {
    pub title_index: u32,
    pub kind: u32,
    pub name_length: u32,
    pub name: [u16; 1],
    pub padding: u16,
}

/// KEY_VALUE_FULL_INFORMATION: a value's title index, its type, where its data is (from the
/// structure's start) and its length, and its name; the data follows the name.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyValueFullInformation {
    pub title_index: u32,
    pub kind: u32,
    pub data_offset: u32,
    pub data_length: u32,
    pub name_length: u32,
    pub name: [u16; 1],
    pub padding: u16,
}

/// KEY_VALUE_PARTIAL_INFORMATION: a value's title index, its type, and its data.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyValuePartialInformation {
    pub title_index: u32,
    pub kind: u32,
    pub data_length: u32,
    pub data: [u8; 1],
    pub padding: [u8; 3],
}

macro_rules! plain {
    ($($structure:ty),* $(,)?) => {
        // SAFETY: integers, arrays of them and plain structures, without padding: each size
        // asserted below is its fields' sum, every field at its alignment (the padding the headers
        // imply is a field), so every byte belongs to a field and every bit pattern is a value.
        $(unsafe impl Pod for $structure {})*
    };
}

plain!(
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FilePositionInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileNameInformation,
    FileAllInformation,
    FileNetworkOpenInformation,
    FileRenameInformation,
    FileDispositionInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileDirectoryInformation,
    FileFullDirInformation,
    FileBothDirInformation,
    FileNamesInformation,
    FileFsVolumeInformation,
    FileFsSizeInformation,
    FileFsDeviceInformation,
    FileFsAttributeInformation,
    FileFsFullSizeInformation,
    ProcessBasicInformation,
    VmCounters,
    ProcessPriorityClass,
    ThreadBasicInformation,
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    RtlTimeZoneInformation,
    MemoryBasicInformation,
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
);

macro_rules! variable {
    ($($structure:ident . $array:ident),* $(,)?) => {
        $(impl VariableSize for $structure {
            const FIXED_SIZE: usize = offset_of!($structure, $array);
        })*
    };
}

variable!(
    FileNameInformation.file_name,
    FileRenameInformation.file_name,
    FileDirectoryInformation.file_name,
    FileFullDirInformation.file_name,
    FileBothDirInformation.file_name,
    FileNamesInformation.file_name,
    FileFsVolumeInformation.volume_label,
    FileFsAttributeInformation.file_system_name,
    KeyBasicInformation.name,
    KeyNodeInformation.name,
    KeyFullInformation.class,
    KeyValueBasicInformation.name,
    KeyValueFullInformation.name,
    KeyValuePartialInformation.data,
);

const _: () = {
    // The per-file classes.
    assert!(size_of::<FileBasicInformation>() == 40);
    assert!(offset_of!(FileBasicInformation, file_attributes) == 32);
    assert!(size_of::<FileStandardInformation>() == 24);
    assert!(offset_of!(FileStandardInformation, number_of_links) == 16);
    assert!(offset_of!(FileStandardInformation, delete_pending) == 20);
    assert!(size_of::<FileInternalInformation>() == 8);
    assert!(size_of::<FilePositionInformation>() == 8);
    assert!(size_of::<FileNameInformation>() == 8);
    assert!(size_of::<FileAllInformation>() == 104);
    assert!(offset_of!(FileAllInformation, standard) == 40);
    assert!(offset_of!(FileAllInformation, internal) == 64);
    assert!(offset_of!(FileAllInformation, ea) == 72);
    assert!(offset_of!(FileAllInformation, access) == 76);
    assert!(offset_of!(FileAllInformation, position) == 80);
    assert!(offset_of!(FileAllInformation, mode) == 88);
    assert!(offset_of!(FileAllInformation, alignment) == 92);
    assert!(offset_of!(FileAllInformation, name) == 96);
    assert!(size_of::<FileNetworkOpenInformation>() == 56);
    assert!(offset_of!(FileNetworkOpenInformation, allocation_size) == 32);
    assert!(offset_of!(FileNetworkOpenInformation, file_attributes) == 48);
    assert!(size_of::<FileRenameInformation>() == 16);
    assert!(offset_of!(FileRenameInformation, root_directory) == 4);
    assert!(FileRenameInformation::FIXED_SIZE == 12);
    assert!(size_of::<FileDispositionInformation>() == 1);
    assert!(size_of::<FileAllocationInformation>() == 8);
    assert!(size_of::<FileEndOfFileInformation>() == 8);
    // The listings' records.
    assert!(size_of::<FileDirectoryInformation>() == 72);
    assert!(offset_of!(FileDirectoryInformation, creation_time) == 8);
    assert!(offset_of!(FileDirectoryInformation, end_of_file) == 40);
    assert!(offset_of!(FileDirectoryInformation, file_attributes) == 56);
    assert!(FileDirectoryInformation::FIXED_SIZE == 64);
    assert!(size_of::<FileFullDirInformation>() == 72);
    assert!(FileFullDirInformation::FIXED_SIZE == 68);
    assert!(size_of::<FileBothDirInformation>() == 96);
    assert!(offset_of!(FileBothDirInformation, short_name_length) == 68);
    assert!(offset_of!(FileBothDirInformation, short_name) == 70);
    assert!(FileBothDirInformation::FIXED_SIZE == 94);
    assert!(size_of::<FileNamesInformation>() == 16);
    assert!(FileNamesInformation::FIXED_SIZE == 12);
    // The volume classes.
    assert!(size_of::<FileFsVolumeInformation>() == 24);
    assert!(offset_of!(FileFsVolumeInformation, volume_serial_number) == 8);
    assert!(offset_of!(FileFsVolumeInformation, supports_objects) == 16);
    assert!(FileFsVolumeInformation::FIXED_SIZE == 18);
    assert!(size_of::<FileFsSizeInformation>() == 24);
    assert!(size_of::<FileFsDeviceInformation>() == 8);
    assert!(size_of::<FileFsAttributeInformation>() == 16);
    assert!(FileFsAttributeInformation::FIXED_SIZE == 12);
    assert!(size_of::<FileFsFullSizeInformation>() == 32);
    assert!(offset_of!(FileFsFullSizeInformation, sectors_per_allocation_unit) == 24);
    // Processes and threads.
    assert!(size_of::<ProcessBasicInformation>() == 24);
    assert!(offset_of!(ProcessBasicInformation, inherited_from_unique_process_id) == 20);
    assert!(size_of::<VmCounters>() == 44);
    assert!(size_of::<ProcessPriorityClass>() == 2);
    assert!(size_of::<ThreadBasicInformation>() == 28);
    assert!(offset_of!(ThreadBasicInformation, client_id) == 8);
    assert!(offset_of!(ThreadBasicInformation, affinity_mask) == 16);
    assert!(offset_of!(ThreadBasicInformation, base_priority) == 24);
    // The system classes.
    assert!(size_of::<SystemBasicInformation>() == 44);
    assert!(offset_of!(SystemBasicInformation, number_of_processors) == 40);
    assert!(size_of::<SystemProcessorInformation>() == 12);
    assert!(size_of::<SystemPerformanceInformation>() == 0x138);
    assert!(offset_of!(SystemPerformanceInformation, available_pages) == 0x2C);
    assert!(offset_of!(SystemPerformanceInformation, counters) == 0x3C);
    assert!(size_of::<RtlTimeZoneInformation>() == 172);
    assert!(offset_of!(RtlTimeZoneInformation, standard_start) == 68);
    assert!(offset_of!(RtlTimeZoneInformation, daylight_name) == 88);
    assert!(offset_of!(RtlTimeZoneInformation, daylight_bias) == 168);
    // Memory.
    assert!(size_of::<MemoryBasicInformation>() == 28);
    // The registry's replies.
    assert!(size_of::<KeyBasicInformation>() == 24);
    assert!(KeyBasicInformation::FIXED_SIZE == 16);
    assert!(size_of::<KeyNodeInformation>() == 32);
    assert!(KeyNodeInformation::FIXED_SIZE == 24);
    assert!(size_of::<KeyFullInformation>() == 48);
    assert!(KeyFullInformation::FIXED_SIZE == 44);
    assert!(size_of::<KeyValueBasicInformation>() == 16);
    assert!(KeyValueBasicInformation::FIXED_SIZE == 12);
    assert!(size_of::<KeyValueFullInformation>() == 24);
    assert!(KeyValueFullInformation::FIXED_SIZE == 20);
    assert!(size_of::<KeyValuePartialInformation>() == 16);
    assert!(KeyValuePartialInformation::FIXED_SIZE == 12);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// A structure's bytes are its fields at the headers' offsets, little-endian.
    #[test]
    fn a_structure_is_its_fields_bytes() {
        let basic = FileBasicInformation {
            last_write_time: 0x0102_0304_0506_0708,
            file_attributes: 0x21,
            ..Default::default()
        };
        let bytes = basic.as_bytes();
        assert_eq!(&bytes[16..24], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&bytes[32..36], &[0x21, 0, 0, 0]);
        assert_eq!(FileBasicInformation::from_bytes(bytes), Some(basic));
    }

    /// A variable-size structure's fixed part stops where its array starts.
    #[test]
    fn the_fixed_part_precedes_the_array() {
        let record = FileNamesInformation {
            file_index: 3,
            file_name_length: 10,
            ..Default::default()
        };
        assert_eq!(record.fixed_part(), &[0, 0, 0, 0, 3, 0, 0, 0, 10, 0, 0, 0]);
        let partial = KeyValuePartialInformation {
            kind: 4,
            data_length: 4,
            ..Default::default()
        };
        assert_eq!(partial.fixed_part().len(), 12);
    }
}
