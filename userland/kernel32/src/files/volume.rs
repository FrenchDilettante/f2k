//! The volume's calls: GetDriveType, GetDiskFreeSpace, GetDiskFreeSpaceEx and GetVolumeInformation
//! (A and W), each an open of the root path named (the current drive's for none; any directory for
//! GetDiskFreeSpaceEx) and NtQueryVolumeInformationFile, as Windows 2000's kernel32 makes them.
//! GetDriveType does not consult the kernel's drive-letter map (NtQueryInformationProcess's
//! ProcessDeviceMap, not served): it always takes the open's way.

use rtl::status::nt_success;

use super::*;
use crate::base::set_last_nt_error;
use crate::edge::{OutBuf, Text};
use crate::error::bool_answer;

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

/// The current drive's root: what a root path argument not given names.
fn current_root() -> Wide {
    Wide::of(&[u16::from(b'\\')]).expect("a short name")
}

/// A root path argument in UTF-16: the one given, converted, or `\` (the current drive's root)
/// for none.
fn root_path(root: Option<InStr<'_>>) -> Result<Wide, Failure> {
    match root {
        Some(root) => widen(Some(&root)),
        None => Ok(current_root()),
    }
}

/// The same, for a W call's root path, copied.
fn root_path_w(root: Option<InWStr<'_>>) -> Result<Wide, Failure> {
    match root {
        Some(root) => wide(&root),
        None => Ok(current_root()),
    }
}

/// GetDriveTypeW's work: `X:` is taken as its root; the root path's NT form (which must name a
/// root: end in a separator) less its separator — the volume itself — opened for its attributes,
/// and its device (FileFsDeviceInformation) decides: a fixed disk DRIVE_FIXED. A root that is none,
/// or that does not open, is DRIVE_NO_ROOT_DIR (a root that does not convert with its error set).
fn drive_type(path: Result<Wide, Failure>) -> u32 {
    let mut path = match path {
        Ok(path) => path,
        Err(failure) => {
            failure.report();
            return DRIVE_NO_ROOT_DIR;
        }
    };
    let text = path.text();
    if text.len() == 2
        && text[1] == u16::from(b':')
        && (text[0] as u8).is_ascii_alphabetic()
        && text[0] < 0x80
    {
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
    // Part of the NT path, itself a counted string.
    let name = UnicodeString::from_units(volume).expect("part of a counted string");
    let attributes = ObjectAttributes {
        length: 24,
        root_directory: 0,
        object_name: &name,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: core::ptr::null(),
        security_quality_of_service: core::ptr::null(),
    };
    let Ok(handle) = ntcall::open_file(
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &attributes,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SYNCHRONOUS_IO_NONALERT,
    ) else {
        return DRIVE_NO_ROOT_DIR;
    };
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

/// GetDriveTypeA (see [`drive_type`]).
///
/// # Safety
///
/// `root` is null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_GetDriveTypeA")]
pub unsafe extern "system" fn get_drive_type_a(root: *const u8) -> u32 {
    // SAFETY: the caller's string, when given.
    let root = unsafe { InStr::optional(root) };
    drive_type(root_path(root))
}

/// GetDriveTypeW (see [`drive_type`]).
///
/// # Safety
///
/// `root` is null or a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_GetDriveTypeW")]
pub unsafe extern "system" fn get_drive_type_w(root: *const u16) -> u32 {
    // SAFETY: the caller's string, when given.
    let root = unsafe { InWStr::optional(root) };
    drive_type(root_path_w(root))
}

/// The directory a free-space call names opened for listing (FILE_OPEN_FOR_FREE_SPACE_QUERY); a
/// failed open is the status's error, a missing file's ERROR_PATH_NOT_FOUND (it names a directory).
fn open_for_free_space(path: &Wide) -> Result<u32, Failure> {
    let path = NtPath::of(path.terminated()).ok_or(Failure::Error(ERROR_PATH_NOT_FOUND))?;
    let options =
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE | FILE_OPEN_FOR_FREE_SPACE_QUERY;
    open(
        &path,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        options,
    )
    .map_err(|status| {
        // The status's error first (ntdll keeps the status as the thread's last).
        match set_last_nt_error(status) {
            ERROR_FILE_NOT_FOUND => Failure::Error(ERROR_PATH_NOT_FOUND),
            error => Failure::Error(error),
        }
    })
}

/// GetDiskFreeSpaceW's work: the root path's directory opened for listing (a missing one
/// ERROR_PATH_NOT_FOUND), the volume's size (FileFsSizeInformation): sectors per cluster, bytes
/// per sector, free and total clusters, each where asked (a count past 32 bits reads as all ones).
fn disk_free_space(
    path: Result<Wide, Failure>,
    mut counts: [Option<Out<'_, u32>>; 4],
) -> Result<(), Failure> {
    let handle = open_for_free_space(&path?)?;
    let mut size = [0u8; 24];
    let status = query_volume(handle, FILE_FS_SIZE_INFORMATION, &mut size);
    close(handle);
    checked(status)?;
    let count = |at: usize| {
        if word(&size, at + 4) != 0 {
            0xFFFF_FFFF
        } else {
            word(&size, at)
        }
    };
    let [sectors_per_cluster, bytes_per_sector, free_clusters, clusters] = &mut counts;
    put(sectors_per_cluster.as_mut(), word(&size, 16));
    put(bytes_per_sector.as_mut(), word(&size, 20));
    put(free_clusters.as_mut(), count(8));
    put(clusters.as_mut(), count(0));
    Ok(())
}

/// GetDiskFreeSpaceA (see [`disk_free_space`]).
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
    // SAFETY: the caller's string and dwords, when given.
    let (root, counts) = unsafe {
        (
            InStr::optional(root),
            [
                Out::optional(sectors_per_cluster),
                Out::optional(bytes_per_sector),
                Out::optional(free_clusters),
                Out::optional(clusters),
            ],
        )
    };
    bool_answer(disk_free_space(root_path(root), counts))
}

/// GetDiskFreeSpaceW (see [`disk_free_space`]).
///
/// # Safety
///
/// `root` is null or a NUL-terminated UTF-16 string; each out pointer is null or points at a dword.
#[unsafe(export_name = "f2k_export_GetDiskFreeSpaceW")]
pub unsafe extern "system" fn get_disk_free_space_w(
    root: *const u16,
    sectors_per_cluster: *mut u32,
    bytes_per_sector: *mut u32,
    free_clusters: *mut u32,
    clusters: *mut u32,
) -> u32 {
    // SAFETY: the caller's string and dwords, when given.
    let (root, counts) = unsafe {
        (
            InWStr::optional(root),
            [
                Out::optional(sectors_per_cluster),
                Out::optional(bytes_per_sector),
                Out::optional(free_clusters),
                Out::optional(clusters),
            ],
        )
    };
    bool_answer(disk_free_space(root_path_w(root), counts))
}

/// GetDiskFreeSpaceExW's work: the directory named (the current drive's root for none: any
/// directory of the volume, not only its root) opened for listing — a file is ERROR_DIRECTORY
/// (STATUS_NOT_A_DIRECTORY), a missing directory or volume ERROR_PATH_NOT_FOUND, an empty name too
/// (no NT path is made of it) — then its volume's sizes (FileFsFullSizeInformation) in bytes: the
/// free bytes the caller may use, the total, and the total free, each where asked.
fn disk_free_space_ex(
    path: Result<Wide, Failure>,
    mut sizes: [Option<Out<'_, u64>>; 3],
) -> Result<(), Failure> {
    let handle = open_for_free_space(&path?)?;
    let mut size = [0u8; 32];
    let status = query_volume(handle, FILE_FS_FULL_SIZE_INFORMATION, &mut size);
    close(handle);
    checked(status)?;
    let unit = u64::from(word(&size, 24)) * u64::from(word(&size, 28));
    let [caller_free, total, total_free] = &mut sizes;
    put(caller_free.as_mut(), quad(&size, 8).wrapping_mul(unit));
    put(total.as_mut(), quad(&size, 0).wrapping_mul(unit));
    put(total_free.as_mut(), quad(&size, 16).wrapping_mul(unit));
    Ok(())
}

/// GetDiskFreeSpaceExA (see [`disk_free_space_ex`]).
///
/// # Safety
///
/// `directory` is null or a NUL-terminated string; each out pointer is null or points at a
/// quadword.
#[unsafe(export_name = "f2k_export_GetDiskFreeSpaceExA")]
pub unsafe extern "system" fn get_disk_free_space_ex_a(
    directory: *const u8,
    caller_free: *mut u64,
    total: *mut u64,
    total_free: *mut u64,
) -> u32 {
    // SAFETY: the caller's string and quadwords, when given.
    let (directory, sizes) = unsafe {
        (
            InStr::optional(directory),
            [
                Out::optional(caller_free),
                Out::optional(total),
                Out::optional(total_free),
            ],
        )
    };
    bool_answer(disk_free_space_ex(root_path(directory), sizes))
}

/// GetDiskFreeSpaceExW (see [`disk_free_space_ex`]).
///
/// # Safety
///
/// `directory` is null or a NUL-terminated UTF-16 string; each out pointer is null or points at a
/// quadword.
#[unsafe(export_name = "f2k_export_GetDiskFreeSpaceExW")]
pub unsafe extern "system" fn get_disk_free_space_ex_w(
    directory: *const u16,
    caller_free: *mut u64,
    total: *mut u64,
    total_free: *mut u64,
) -> u32 {
    // SAFETY: the caller's string and quadwords, when given.
    let (directory, sizes) = unsafe {
        (
            InWStr::optional(directory),
            [
                Out::optional(caller_free),
                Out::optional(total),
                Out::optional(total_free),
            ],
        )
    };
    bool_answer(disk_free_space_ex(root_path_w(directory), sizes))
}

/// What GetVolumeInformation hands back where asked: the volume's name, its serial number, the
/// longest component, the file system's flags and its name.
struct VolumeAnswers<'a> {
    name: Text<'a>,
    serial: Option<Out<'a, u32>>,
    max_component: Option<Out<'a, u32>>,
    flags: Option<Out<'a, u32>>,
    fs_name: Text<'a>,
}

/// GetVolumeInformationW's work: the root path (it must end in a separator and name a root:
/// ERROR_INVALID_NAME otherwise) opened, then the label and serial number
/// (FileFsVolumeInformation) and the file system's flags, longest component and name
/// (FileFsAttributeInformation), each where asked; a name buffer too small is ERROR_BAD_LENGTH.
fn volume_information(
    path: Result<Wide, Failure>,
    mut answers: VolumeAnswers<'_>,
) -> Result<(), Failure> {
    let path = path?;
    let backslash = u16::from(b'\\');
    if path.text().last() != Some(&backslash) {
        return Err(Failure::Error(ERROR_INVALID_NAME));
    }
    let path = NtPath::of(path.terminated()).ok_or(Failure::Error(ERROR_PATH_NOT_FOUND))?;
    if path.units().last() != Some(&backslash) {
        return Err(Failure::Error(ERROR_INVALID_NAME));
    }
    let handle = open(
        &path,
        SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SYNCHRONOUS_IO_NONALERT,
    )
    .map_err(Failure::Status)?;
    // Errors fail the call; a cut name (a warning) is the buffers' to judge.
    let mut volume = [0u8; 24 + 2 * MAX_PATH];
    let mut attribute = [0u8; 16 + 2 * MAX_PATH];
    let mut status = 0;
    if !answers.name.is_null() || answers.serial.is_some() {
        status = query_volume(handle, FILE_FS_VOLUME_INFORMATION, &mut volume);
    }
    let attributes_asked =
        !answers.fs_name.is_null() || answers.max_component.is_some() || answers.flags.is_some();
    if unless_error(status).is_ok() && attributes_asked {
        status = query_volume(handle, FILE_FS_ATTRIBUTE_INFORMATION, &mut attribute);
    }
    close(handle);
    unless_error(status)?;
    let units = |bytes: &[u8], at: usize, length: usize| -> [u16; MAX_PATH] {
        let mut out = [0u16; MAX_PATH];
        for (index, unit) in out.iter_mut().enumerate().take((length / 2).min(MAX_PATH)) {
            *unit = u16::from_le_bytes([bytes[at + 2 * index], bytes[at + 2 * index + 1]]);
        }
        out
    };
    // A name into a caller's buffer, with its terminator; ERROR_BAD_LENGTH when it does not fit.
    let put_name = |out: &mut Text<'_>, name: &[u16]| {
        if name.len() >= out.len() {
            return Err(Failure::Error(ERROR_BAD_LENGTH));
        }
        out.put_terminated(name);
        Ok(())
    };
    if !answers.name.is_null() {
        let length = (word(&volume, 12) as usize / 2).min(MAX_PATH);
        put_name(&mut answers.name, &units(&volume, 18, 2 * length)[..length])?;
    }
    put(answers.serial.as_mut(), word(&volume, 8));
    if !answers.fs_name.is_null() {
        let length = (word(&attribute, 8) as usize / 2).min(MAX_PATH);
        put_name(
            &mut answers.fs_name,
            &units(&attribute, 12, 2 * length)[..length],
        )?;
    }
    put(answers.max_component.as_mut(), word(&attribute, 4));
    put(answers.flags.as_mut(), word(&attribute, 0));
    Ok(())
}

/// GetVolumeInformationA (see [`volume_information`]).
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
    // SAFETY: the caller's string when given, its buffers (null ones not asked for), and its
    // dwords when given (the contract).
    let (root, answers) = unsafe {
        (
            InStr::optional(root),
            VolumeAnswers {
                name: Text::Ansi(OutBuf::new(name, name_size as usize)),
                serial: Out::optional(serial),
                max_component: Out::optional(max_component),
                flags: Out::optional(flags),
                fs_name: Text::Ansi(OutBuf::new(fs_name, fs_size as usize)),
            },
        )
    };
    bool_answer(volume_information(root_path(root), answers))
}

/// GetVolumeInformationW (see [`volume_information`]).
///
/// # Safety
///
/// `root` is null or a NUL-terminated UTF-16 string; the buffers hold their sizes in characters;
/// each other out pointer is null or points at a dword.
#[unsafe(export_name = "f2k_export_GetVolumeInformationW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn get_volume_information_w(
    root: *const u16,
    name: *mut u16,
    name_size: u32,
    serial: *mut u32,
    max_component: *mut u32,
    flags: *mut u32,
    fs_name: *mut u16,
    fs_size: u32,
) -> u32 {
    // SAFETY: as GetVolumeInformationA's, the string and buffers UTF-16.
    let (root, answers) = unsafe {
        (
            InWStr::optional(root),
            VolumeAnswers {
                name: Text::Wide(OutBuf::new(name, name_size as usize)),
                serial: Out::optional(serial),
                max_component: Out::optional(max_component),
                flags: Out::optional(flags),
                fs_name: Text::Wide(OutBuf::new(fs_name, fs_size as usize)),
            },
        )
    };
    bool_answer(volume_information(root_path_w(root), answers))
}
