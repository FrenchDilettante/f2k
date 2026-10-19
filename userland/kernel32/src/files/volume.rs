//! The volume's calls: GetDriveTypeA, GetDiskFreeSpaceA and GetVolumeInformationA, each an open of
//! the root path named (the current drive's for none) and NtQueryVolumeInformationFile, as Windows
//! 2000's kernel32 makes them. GetDriveType does not consult the kernel's drive-letter map
//! (NtQueryInformationProcess's ProcessDeviceMap, not served): it always takes the open's way.

use rtl::cp1252;
use rtl::status::nt_success;

use super::*;
use crate::base::set_last_nt_error;

/// GetDriveType's answers.
const DRIVE_UNKNOWN: u32 = 0;
const DRIVE_NO_ROOT_DIR: u32 = 1;
const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const DRIVE_REMOTE: u32 = 4;
const DRIVE_CDROM: u32 = 5;
const DRIVE_RAMDISK: u32 = 6;

/// FILE_FS_DEVICE_INFORMATION's characteristics.
const FILE_REMOVABLE_MEDIA: u32 = 0x1;
const FILE_REMOTE_DEVICE: u32 = 0x10;

/// A root path argument in UTF-16: the one given, or `\` (the current drive's root) for none.
///
/// # Safety
///
/// `root` is null or a NUL-terminated string.
unsafe fn root_path(root: *const u8) -> Option<Wide> {
    if root.is_null() {
        return Wide::of(&[u16::from(b'\\')]);
    }
    // SAFETY: the caller's string.
    unsafe { widen(root) }
}

/// Query `class` of the open volume `handle` into `out`: the status.
fn query_volume(handle: u32, class: u32, out: &mut [u8]) -> u32 {
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, into the buffer of its length.
    unsafe { nt::NtQueryVolumeInformationFile(handle, &mut io_status, out.as_mut_ptr(), out.len() as u32, class) }
}

/// GetDriveTypeA: `X:` is taken as its root; the root path's NT form (which must name a root: end
/// in a separator) less its separator — the volume itself — opened for its attributes, and its
/// device (FileFsDeviceInformation) decides: a fixed disk DRIVE_FIXED. A root that is none, or that
/// does not open, is DRIVE_NO_ROOT_DIR.
///
/// # Safety
///
/// `root` is null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_GetDriveTypeA")]
pub unsafe extern "system" fn get_drive_type_a(root: *const u8) -> u32 {
    // SAFETY: the caller's string.
    let Some(mut path) = (unsafe { root_path(root) }) else {
        return DRIVE_NO_ROOT_DIR;
    };
    let text = path.text();
    if text.len() == 2 && text[1] == u16::from(b':') && (text[0] as u8).is_ascii_alphabetic() && text[0] < 0x80 {
        path.units[2] = u16::from(b'\\');
        path.units[3] = 0;
        path.length = 3;
    }
    let Some(nt_path) = NtPath::of(path.terminated()) else {
        return DRIVE_NO_ROOT_DIR;
    };
    let units = nt_path.units();
    if units.last() != Some(&u16::from(b'\\')) {
        return DRIVE_NO_ROOT_DIR;
    }
    let volume = &units[..units.len() - 1];
    let name = UnicodeString { length: (2 * volume.len()) as u16, maximum_length: (2 * volume.len()) as u16, buffer: volume.as_ptr() as *mut u16 };
    let attributes = ObjectAttributes {
        length: 24,
        root_directory: 0,
        object_name: &name,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: core::ptr::null(),
        security_quality_of_service: core::ptr::null(),
    };
    let mut handle = 0;
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, over the attributes above.
    let status = unsafe {
        nt::NtOpenFile(
            &mut handle,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &attributes,
            &mut io_status,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_SYNCHRONOUS_IO_NONALERT,
        )
    };
    if !nt_success(status) {
        return DRIVE_NO_ROOT_DIR;
    }
    let mut device = [0u8; 8];
    let status = query_volume(handle, FILE_FS_DEVICE_INFORMATION, &mut device);
    close(handle);
    if !nt_success(status) {
        return DRIVE_UNKNOWN;
    }
    let (kind, characteristics) = (word(&device, 0), word(&device, 4));
    if characteristics & FILE_REMOTE_DEVICE != 0 {
        return DRIVE_REMOTE;
    }
    match kind {
        // Network, its file system, a redirector.
        0x12 | 0x14 | 0x28 => DRIVE_REMOTE,
        0x02 | 0x03 => DRIVE_CDROM,
        0x24 => DRIVE_RAMDISK,
        0x07 | 0x08 if characteristics & FILE_REMOVABLE_MEDIA != 0 => DRIVE_REMOVABLE,
        0x07 | 0x08 => DRIVE_FIXED,
        _ => DRIVE_UNKNOWN,
    }
}

/// GetDiskFreeSpaceA: the root path's directory opened for listing (a missing one
/// ERROR_PATH_NOT_FOUND), the volume's size (FileFsSizeInformation): sectors per cluster, bytes
/// per sector, free and total clusters, each where asked (a count past 32 bits reads as all ones).
///
/// # Safety
///
/// `root` is null or a NUL-terminated string; each out pointer is null or points at a dword.
#[unsafe(export_name = "f2k_export_GetDiskFreeSpaceA")]
pub unsafe extern "system" fn get_disk_free_space_a(
    root: *const u8,
    sectors_per_cluster: *mut u32,
    bytes_per_sector: *mut u32,
    free_clusters: *mut u32,
    clusters: *mut u32,
) -> u32 {
    // SAFETY: the caller's string.
    let Some(path) = (unsafe { root_path(root) }) else {
        return 0;
    };
    let Some(path) = NtPath::of(path.terminated()) else {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return 0;
    };
    let options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE | FILE_OPEN_FOR_FREE_SPACE_QUERY;
    let handle = match open(&path, FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, options) {
        Ok(handle) => handle,
        Err(status) => {
            set_last_nt_error(status);
            if crate::base::last_error() == ERROR_FILE_NOT_FOUND {
                set_last_error(ERROR_PATH_NOT_FOUND);
            }
            return 0;
        }
    };
    let mut size = [0u8; 24];
    let status = query_volume(handle, FILE_FS_SIZE_INFORMATION, &mut size);
    close(handle);
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    let count = |at: usize| if word(&size, at + 4) != 0 { 0xFFFF_FFFF } else { word(&size, at) };
    // SAFETY: the caller's slots.
    unsafe {
        put(sectors_per_cluster, word(&size, 16));
        put(bytes_per_sector, word(&size, 20));
        put(free_clusters, count(8));
        put(clusters, count(0));
    }
    1
}

/// GetVolumeInformationA: the root path (it must end in a separator and name a root:
/// ERROR_INVALID_NAME otherwise) opened, then the label and serial number
/// (FileFsVolumeInformation) and the file system's flags, longest component and name
/// (FileFsAttributeInformation), each where asked; a name buffer too small is ERROR_BAD_LENGTH.
///
/// # Safety
///
/// `root` is null or a NUL-terminated string; the buffers hold their sizes; each other out pointer
/// is null or points at a dword.
#[unsafe(export_name = "f2k_export_GetVolumeInformationA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn get_volume_information_a(
    root: *const u8,
    name: *mut u8,
    name_size: u32,
    serial: *mut u32,
    max_component: *mut u32,
    flags: *mut u32,
    fs_name: *mut u8,
    fs_size: u32,
) -> u32 {
    // SAFETY: the caller's string.
    let Some(path) = (unsafe { root_path(root) }) else {
        return 0;
    };
    let backslash = u16::from(b'\\');
    if path.text().last() != Some(&backslash) {
        set_last_error(ERROR_INVALID_NAME);
        return 0;
    }
    let Some(path) = NtPath::of(path.terminated()) else {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return 0;
    };
    if path.units().last() != Some(&backslash) {
        set_last_error(ERROR_INVALID_NAME);
        return 0;
    }
    let handle = match open(&path, SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT) {
        Ok(handle) => handle,
        Err(status) => {
            set_last_nt_error(status);
            return 0;
        }
    };
    // Errors fail the call; a cut name (a warning) is the buffers' to judge.
    let failed = |status: u32| status & 0xC000_0000 == 0xC000_0000;
    let mut volume = [0u8; 24 + 2 * MAX_PATH];
    let mut attribute = [0u8; 16 + 2 * MAX_PATH];
    let mut status = 0;
    if !name.is_null() || !serial.is_null() {
        status = query_volume(handle, FILE_FS_VOLUME_INFORMATION, &mut volume);
    }
    if !failed(status) && (!fs_name.is_null() || !max_component.is_null() || !flags.is_null()) {
        status = query_volume(handle, FILE_FS_ATTRIBUTE_INFORMATION, &mut attribute);
    }
    close(handle);
    if failed(status) {
        set_last_nt_error(status);
        return 0;
    }
    let units = |bytes: &[u8], at: usize, length: usize| -> [u16; MAX_PATH] {
        let mut out = [0u16; MAX_PATH];
        for (index, unit) in out.iter_mut().enumerate().take((length / 2).min(MAX_PATH)) {
            *unit = u16::from_le_bytes([bytes[at + 2 * index], bytes[at + 2 * index + 1]]);
        }
        out
    };
    // A name into a caller's buffer of `size` characters, with its terminator.
    let put_name = |out: *mut u8, size: u32, name: &[u16]| -> bool {
        if name.len() >= size as usize {
            return false;
        }
        for (at, &unit) in name.iter().enumerate() {
            // SAFETY: the caller's buffer holds the name and its terminator.
            unsafe { out.add(at).write(cp1252::wc_to_mb(unit)) };
        }
        // SAFETY: as above.
        unsafe { out.add(name.len()).write(0) };
        true
    };
    if !name.is_null() {
        let length = (word(&volume, 12) as usize / 2).min(MAX_PATH);
        if !put_name(name, name_size, &units(&volume, 18, 2 * length)[..length]) {
            set_last_error(ERROR_BAD_LENGTH);
            return 0;
        }
    }
    // SAFETY: the caller's slot.
    unsafe { put(serial, word(&volume, 8)) };
    if !fs_name.is_null() {
        let length = (word(&attribute, 8) as usize / 2).min(MAX_PATH);
        if !put_name(fs_name, fs_size, &units(&attribute, 12, 2 * length)[..length]) {
            set_last_error(ERROR_BAD_LENGTH);
            return 0;
        }
    }
    // SAFETY: the caller's slots.
    unsafe {
        put(max_component, word(&attribute, 4));
        put(flags, word(&attribute, 0));
    }
    1
}
