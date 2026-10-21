//! The calls on a file handle: CreateFileA (CreateFileW's work over NtCreateFile), ReadFile and
//! WriteFile (NtReadFile, NtWriteFile; a console handle's bytes go to the console), SetFilePointer,
//! FlushFileBuffers, GetFileType, the size, times and identity of an open file, SetFileTime and
//! SetEndOfFile — as Windows 2000's kernel32 makes them of the information classes.

use rtl::status::nt_success;

use super::*;
use crate::base::{is_console_handle, set_last_nt_error, standard_handle};
use crate::console;

/// CreateFileA's dispositions.
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;

/// CreateFileA's flags.
const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
const FILE_FLAG_RANDOM_ACCESS: u32 = 0x1000_0000;
const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_POSIX_SEMANTICS: u32 = 0x0100_0000;
/// The attribute bits a create carries (FILE_ATTRIBUTE_VALID_FLAGS), the directory bit aside.
const FILE_ATTRIBUTE_VALID_FLAGS: u32 = 0x7FB7;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

/// GetFileType's answers.
const FILE_TYPE_UNKNOWN: u32 = 0;
const FILE_TYPE_DISK: u32 = 1;
const FILE_TYPE_CHAR: u32 = 2;
const FILE_TYPE_PIPE: u32 = 3;

/// SetFilePointer's move methods and failure.
const FILE_BEGIN: u32 = 0;
const FILE_CURRENT: u32 = 1;
const FILE_END: u32 = 2;
const INVALID_SET_FILE_POINTER: u32 = 0xFFFF_FFFF;

/// CreateFileW's work, the W form every create shares (CreateFileA, CopyFileA): the disposition
/// mapped (TRUNCATE_EXISTING asks GENERIC_WRITE), the path made an NT one, the flags mapped to
/// create options (no backup semantics: no directory; delete-on-close: DELETE access too), and
/// NtCreateFile asked for the access with SYNCHRONIZE and FILE_READ_ATTRIBUTES. On success the
/// last error is ERROR_ALREADY_EXISTS when CREATE_ALWAYS or OPEN_ALWAYS found the file, cleared
/// otherwise, and TRUNCATE_EXISTING cuts the file (FileAllocationInformation). A name already
/// taken under CREATE_NEW is ERROR_FILE_EXISTS; any other failure the status's error.
///
/// # Safety
///
/// `security` is null or points at a SECURITY_ATTRIBUTES.
pub unsafe fn create_file_w(
    name: &Wide,
    access: u32,
    share: u32,
    security: *const SecurityAttributes,
    disposition: u32,
    flags: u32,
) -> u32 {
    let create = match disposition {
        CREATE_NEW => FILE_CREATE,
        CREATE_ALWAYS => FILE_OVERWRITE_IF,
        OPEN_EXISTING => FILE_OPEN,
        OPEN_ALWAYS => FILE_OPEN_IF,
        TRUNCATE_EXISTING if access & GENERIC_WRITE != 0 => FILE_OPEN,
        _ => {
            set_last_nt_error(STATUS_INVALID_PARAMETER);
            return INVALID_HANDLE_VALUE;
        }
    };
    let Some(path) = NtPath::of(name.terminated()) else {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    };
    // SAFETY: the caller's structure, when given.
    let mut attributes = path.attributes(unsafe { inherits(security) });
    if flags & FILE_FLAG_POSIX_SEMANTICS != 0 {
        attributes.attributes &= !OBJ_CASE_INSENSITIVE;
    }
    let mut access = access;
    let mut options = 0;
    let mapped = [
        (FILE_FLAG_NO_BUFFERING, FILE_NO_INTERMEDIATE_BUFFERING),
        (FILE_FLAG_WRITE_THROUGH, FILE_WRITE_THROUGH),
        (FILE_FLAG_SEQUENTIAL_SCAN, FILE_SEQUENTIAL_ONLY),
        (FILE_FLAG_RANDOM_ACCESS, FILE_RANDOM_ACCESS),
        (FILE_FLAG_BACKUP_SEMANTICS, FILE_OPEN_FOR_BACKUP_INTENT),
    ];
    for (flag, option) in mapped {
        if flags & flag != 0 {
            options |= option;
        }
    }
    if flags & FILE_FLAG_OVERLAPPED == 0 {
        options |= FILE_SYNCHRONOUS_IO_NONALERT;
    }
    if flags & FILE_FLAG_DELETE_ON_CLOSE != 0 {
        options |= FILE_DELETE_ON_CLOSE;
        access |= DELETE;
    }
    // Backup semantics allow directories to be opened.
    if flags & FILE_FLAG_BACKUP_SEMANTICS == 0 {
        options |= FILE_NON_DIRECTORY_FILE;
    }
    let mut handle = 0;
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, over the attributes above.
    let status = unsafe {
        nt::NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
            &attributes,
            &mut io_status,
            core::ptr::null(),
            flags & (FILE_ATTRIBUTE_VALID_FLAGS & !FILE_ATTRIBUTE_DIRECTORY),
            share,
            create,
            options,
            core::ptr::null(),
            0,
        )
    };
    drop(path);
    if !nt_success(status) {
        set_last_nt_error(status);
        if status == STATUS_OBJECT_NAME_COLLISION {
            set_last_error(ERROR_FILE_EXISTS);
        }
        return INVALID_HANDLE_VALUE;
    }
    let found = (disposition == CREATE_ALWAYS && io_status.information == FILE_OVERWRITTEN)
        || (disposition == OPEN_ALWAYS && io_status.information == FILE_OPENED);
    set_last_error(if found { ERROR_ALREADY_EXISTS } else { 0 });
    if disposition == TRUNCATE_EXISTING {
        let status = set(handle, FILE_ALLOCATION_INFORMATION, &0u64.to_le_bytes());
        if !nt_success(status) {
            close(handle);
            set_last_nt_error(status);
            return INVALID_HANDLE_VALUE;
        }
    }
    handle
}

/// CreateFileA: the name converted, then CreateFileW's work ([`create_file_w`]); the template file
/// is not consulted.
///
/// # Safety
///
/// `name` is a NUL-terminated string; `security` null or a SECURITY_ATTRIBUTES.
#[unsafe(export_name = "f2k_export_CreateFileA")]
pub unsafe extern "system" fn create_file_a(
    name: *const u8,
    access: u32,
    share: u32,
    security: *const SecurityAttributes,
    disposition: u32,
    flags: u32,
    _template: u32,
) -> u32 {
    // SAFETY: the caller's string.
    let Some(name) = (unsafe { widen(name) }) else {
        return INVALID_HANDLE_VALUE;
    };
    // SAFETY: the caller's structure.
    unsafe { create_file_w(&name, access, share, security, disposition, flags) }
}

/// An OVERLAPPED, as the caller passes it: its I/O status (Internal, InternalHigh), its offset and
/// its event.
#[repr(C)]
pub struct Overlapped {
    pub internal: u32,
    pub internal_high: u32,
    pub offset: u32,
    pub offset_high: u32,
    pub event: u32,
}

/// What a synchronous read or write reports: TRUE with the count, or FALSE with the status's error
/// (the count of a warning kept).
///
/// # Safety
///
/// `count` is null or points at a dword.
unsafe fn transferred(status: u32, io_status: &IoStatus, count: *mut u32) -> u32 {
    if nt_success(status) {
        // SAFETY: the caller's slot.
        unsafe { put(count, io_status.information) };
        return 1;
    }
    if status & 0xC000_0000 == 0x8000_0000 {
        // SAFETY: as above.
        unsafe { put(count, io_status.information) };
    }
    set_last_nt_error(status);
    0
}

/// An overlapped read or write's answer, Windows 2000's: started at the OVERLAPPED's offset with
/// its event, its I/O status there; TRUE with the count once complete (every F2K file completes at
/// once), FALSE with the status's error otherwise (end of file: a count of zero).
///
/// # Safety
///
/// `overlapped` points at an OVERLAPPED; `count` is null or points at a dword.
unsafe fn overlapped_transfer(
    overlapped: *mut Overlapped,
    count: *mut u32,
    start: impl FnOnce(u32, usize, *mut IoStatus, *const u64) -> u32,
) -> u32 {
    // SAFETY: the caller's OVERLAPPED.
    let overlapped = unsafe { &mut *overlapped };
    overlapped.internal = STATUS_PENDING;
    let offset = u64::from(overlapped.offset) | u64::from(overlapped.offset_high) << 32;
    let context = if overlapped.event & 1 != 0 {
        0
    } else {
        overlapped as *mut Overlapped as usize
    };
    let status = start(
        overlapped.event,
        context,
        &mut overlapped.internal as *mut u32 as *mut IoStatus,
        &offset,
    );
    if nt_success(status) && status != STATUS_PENDING {
        // SAFETY: the caller's slot.
        unsafe { put(count, overlapped.internal_high) };
        return 1;
    }
    if status == STATUS_END_OF_FILE {
        // SAFETY: as above.
        unsafe { put(count, 0) };
    }
    set_last_nt_error(status);
    0
}

/// ReadFile: `count` bytes at most from the file's position (or an OVERLAPPED's offset) into the
/// caller's buffer, the count read stored (zeroed first); a read at or past the end reads nothing
/// and succeeds. A console handle's read is the console's (ReadConsoleA, as Windows 2000's ReadFile
/// hands it: F2K's console has no keyboard, so its input handle reads nothing and succeeds, and any
/// other console handle is ERROR_INVALID_HANDLE).
///
/// # Safety
///
/// `buffer` holds `count` bytes; `read` is null or points at a dword; `overlapped` is null or
/// points at an OVERLAPPED.
#[unsafe(export_name = "f2k_export_ReadFile")]
pub unsafe extern "system" fn read_file(
    file: u32,
    buffer: *mut u8,
    count: u32,
    read: *mut u32,
    overlapped: *mut Overlapped,
) -> u32 {
    // SAFETY: the caller's slot.
    unsafe { put(read, 0) };
    let file = standard_handle(file);
    if is_console_handle(file) {
        // SAFETY: the caller's arguments.
        return unsafe { console::read_console(file, buffer, count, read) };
    }
    if !overlapped.is_null() {
        // SAFETY: the caller's OVERLAPPED and buffer; ntdll's export.
        return unsafe {
            overlapped_transfer(overlapped, read, |event, context, io_status, offset| {
                nt::NtReadFile(
                    file,
                    event,
                    0,
                    context,
                    io_status,
                    buffer,
                    count,
                    offset,
                    core::ptr::null(),
                )
            })
        };
    }
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, into the caller's buffer.
    let status = unsafe {
        nt::NtReadFile(
            file,
            0,
            0,
            0,
            &mut io_status,
            buffer,
            count,
            core::ptr::null(),
            core::ptr::null(),
        )
    };
    if status == STATUS_END_OF_FILE {
        // SAFETY: the caller's slot.
        unsafe { put(read, 0) };
        return 1;
    }
    // SAFETY: as above.
    unsafe { transferred(status, &io_status, read) }
}

/// WriteFile: `count` bytes of the caller's at the file's position (or an OVERLAPPED's offset), the
/// count written stored (zeroed first, so a failure reports none, unverified). A console handle's
/// bytes go to the console (WriteConsoleA, the OVERLAPPED its reserved argument), as Windows 2000's
/// WriteFile hands them.
///
/// # Safety
///
/// `buffer` holds `count` bytes; `written` is null or points at a dword; `overlapped` is null or
/// points at an OVERLAPPED.
#[unsafe(export_name = "f2k_export_WriteFile")]
pub unsafe extern "system" fn write_file(
    file: u32,
    buffer: *const u8,
    count: u32,
    written: *mut u32,
    overlapped: *mut Overlapped,
) -> u32 {
    // SAFETY: the caller's slot.
    unsafe { put(written, 0) };
    let file = standard_handle(file);
    if is_console_handle(file) {
        // SAFETY: the caller's arguments.
        return unsafe {
            console::write_console_a(file, buffer, count, written, overlapped as *const u8)
        };
    }
    if !overlapped.is_null() {
        // SAFETY: the caller's OVERLAPPED and buffer; ntdll's export.
        return unsafe {
            overlapped_transfer(overlapped, written, |event, context, io_status, offset| {
                nt::NtWriteFile(
                    file,
                    event,
                    0,
                    context,
                    io_status,
                    buffer,
                    count,
                    offset,
                    core::ptr::null(),
                )
            })
        };
    }
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, from the caller's buffer.
    let status = unsafe {
        nt::NtWriteFile(
            file,
            0,
            0,
            0,
            &mut io_status,
            buffer,
            count,
            core::ptr::null(),
            core::ptr::null(),
        )
    };
    // SAFETY: the caller's slot.
    unsafe { transferred(status, &io_status, written) }
}

/// SetFilePointer, Windows 2000's: the distance (the 64-bit pair with a high dword, the
/// sign-extended low dword without) from the start, the position (FilePositionInformation) or the
/// end (FileStandardInformation's), then set (FilePositionInformation): the new position's low
/// dword, its high one stored. A bad move method is ERROR_INVALID_PARAMETER, a target before the
/// start ERROR_NEGATIVE_SEEK, one past 4 GiB without a high dword ERROR_INVALID_PARAMETER, a
/// console handle ERROR_INVALID_HANDLE; a success reading as INVALID_SET_FILE_POINTER clears the
/// last error.
///
/// # Safety
///
/// `high` is null or points at a dword.
#[unsafe(export_name = "f2k_export_SetFilePointer")]
pub unsafe extern "system" fn set_file_pointer(
    file: u32,
    low: u32,
    high: *mut i32,
    method: u32,
) -> u32 {
    if is_console_handle(file) {
        set_last_nt_error(STATUS_INVALID_HANDLE);
        return INVALID_SET_FILE_POINTER;
    }
    let distance = if high.is_null() {
        i64::from(low as i32)
    } else {
        // SAFETY: the caller's high dword.
        (i64::from(unsafe { high.read_unaligned() }) << 32) | i64::from(low)
    };
    let target = match method {
        FILE_BEGIN => distance,
        FILE_CURRENT => {
            let mut position = [0u8; 8];
            let status = query(file, FILE_POSITION_INFORMATION, &mut position);
            if !nt_success(status) {
                set_last_nt_error(status);
                return INVALID_SET_FILE_POINTER;
            }
            (quad(&position, 0) as i64).wrapping_add(distance)
        }
        FILE_END => {
            let mut standard = [0u8; 24];
            let status = query(file, FILE_STANDARD_INFORMATION, &mut standard);
            if !nt_success(status) {
                set_last_nt_error(status);
                return INVALID_SET_FILE_POINTER;
            }
            (quad(&standard, 8) as i64).wrapping_add(distance)
        }
        _ => {
            set_last_error(ERROR_INVALID_PARAMETER);
            return INVALID_SET_FILE_POINTER;
        }
    };
    if target < 0 {
        set_last_error(ERROR_NEGATIVE_SEEK);
        return INVALID_SET_FILE_POINTER;
    }
    if high.is_null() && (target >> 32) & 0x7FFF_FFFF != 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_SET_FILE_POINTER;
    }
    let status = set(
        file,
        FILE_POSITION_INFORMATION,
        &(target as u64).to_le_bytes(),
    );
    if !nt_success(status) {
        set_last_nt_error(status);
        if !high.is_null() {
            // SAFETY: as above.
            unsafe { high.write_unaligned(-1) };
        }
        return INVALID_SET_FILE_POINTER;
    }
    if !high.is_null() {
        // SAFETY: as above.
        unsafe { high.write_unaligned((target >> 32) as i32) };
    }
    if target as u32 == INVALID_SET_FILE_POINTER {
        set_last_error(0);
    }
    target as u32
}

/// FlushFileBuffers: the file's writes to the volume (NtFlushBuffersFile); a console handle's
/// input buffer emptied (FlushConsoleInputBuffer, as Windows 2000's hands it — an output handle is
/// ERROR_INVALID_HANDLE there: the console's writes are never buffered).
#[unsafe(export_name = "f2k_export_FlushFileBuffers")]
pub extern "system" fn flush_file_buffers(file: u32) -> u32 {
    let file = standard_handle(file);
    if is_console_handle(file) {
        return console::flush_console_input_buffer(file);
    }
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export.
    let status = unsafe { nt::NtFlushBuffersFile(file, &mut io_status) };
    if nt_success(status) {
        1
    } else {
        set_last_nt_error(status);
        0
    }
}

/// GetFileType: a console handle naming a console object is a character device
/// (VerifyConsoleIoHandle, as Windows 2000's asks the console; one naming none is FILE_TYPE_UNKNOWN
/// with ERROR_INVALID_HANDLE); any other handle's device type (FileFsDeviceInformation) decides — a
/// disk's file FILE_TYPE_DISK. A null handle, and one the device query fails for, is
/// FILE_TYPE_UNKNOWN with the error.
#[unsafe(export_name = "f2k_export_GetFileType")]
pub extern "system" fn get_file_type(file: u32) -> u32 {
    let file = standard_handle(file);
    if is_console_handle(file) {
        if console::verify_console_io_handle(file) {
            return FILE_TYPE_CHAR;
        }
        set_last_error(ERROR_INVALID_HANDLE);
        return FILE_TYPE_UNKNOWN;
    }
    if file == 0 {
        set_last_error(ERROR_INVALID_HANDLE);
        return FILE_TYPE_UNKNOWN;
    }
    let mut device = [0u8; 8];
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, into the structure above.
    let status = unsafe {
        nt::NtQueryVolumeInformationFile(
            file,
            &mut io_status,
            device.as_mut_ptr(),
            8,
            FILE_FS_DEVICE_INFORMATION,
        )
    };
    if !nt_success(status) {
        set_last_nt_error(status);
        return FILE_TYPE_UNKNOWN;
    }
    match word(&device, 0) {
        // Screen, keyboard, mouse, null, parallel, printer, serial, sound, modem.
        0x1C | 0x0B | 0x0F | 0x15 | 0x16 | 0x18 | 0x1B | 0x1D | 0x2B => FILE_TYPE_CHAR,
        0x11 => FILE_TYPE_PIPE,
        // CD-ROM and its file system, controller, datalink, DFS, disk and its file system, virtual
        // disk.
        0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x24 => FILE_TYPE_DISK,
        _ => {
            set_last_error(0);
            FILE_TYPE_UNKNOWN
        }
    }
}

/// GetFileSize: the end of file's low dword (FileStandardInformation), its high one stored when
/// asked; INVALID_FILE_SIZE with the error on failure, and a success reading as it clears the last
/// error.
///
/// # Safety
///
/// `high` is null or points at a dword.
#[unsafe(export_name = "f2k_export_GetFileSize")]
pub unsafe extern "system" fn get_file_size(file: u32, high: *mut u32) -> u32 {
    let mut standard = [0u8; 24];
    let status = query(file, FILE_STANDARD_INFORMATION, &mut standard);
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0xFFFF_FFFF;
    }
    // SAFETY: the caller's slot.
    unsafe { put(high, word(&standard, 12)) };
    let low = word(&standard, 8);
    if low == 0xFFFF_FFFF {
        set_last_error(0);
    }
    low
}

/// GetFileTime: each FILETIME asked for (FileBasicInformation's creation, last access, last write).
///
/// # Safety
///
/// Each pointer is null or points at a FILETIME.
#[unsafe(export_name = "f2k_export_GetFileTime")]
pub unsafe extern "system" fn get_file_time(
    file: u32,
    created: *mut u64,
    accessed: *mut u64,
    written: *mut u64,
) -> u32 {
    let mut basic = [0u8; 40];
    let status = query(file, FILE_BASIC_INFORMATION, &mut basic);
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    // SAFETY: the caller's slots.
    unsafe {
        put_time(created, quad(&basic, 0));
        put_time(accessed, quad(&basic, 8));
        put_time(written, quad(&basic, 16));
    }
    1
}

/// SetFileTime: the times given (FileBasicInformation, zero for the others and the attributes:
/// left as they are).
///
/// # Safety
///
/// Each pointer is null or points at a FILETIME.
#[unsafe(export_name = "f2k_export_SetFileTime")]
pub unsafe extern "system" fn set_file_time(
    file: u32,
    created: *const u64,
    accessed: *const u64,
    written: *const u64,
) -> u32 {
    let mut basic = [0u8; 40];
    for (at, time) in [(0, created), (8, accessed), (16, written)] {
        if !time.is_null() {
            // SAFETY: the caller's FILETIME.
            basic[at..at + 8].copy_from_slice(&unsafe { time.read_unaligned() }.to_le_bytes());
        }
    }
    let status = set(file, FILE_BASIC_INFORMATION, &basic);
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    1
}

/// GetFileInformationByHandle: the volume's serial number (FileFsVolumeInformation), then
/// FileAllInformation's attributes, times, size, links and index; a console handle is
/// ERROR_INVALID_HANDLE.
///
/// # Safety
///
/// `info` points at a BY_HANDLE_FILE_INFORMATION.
#[unsafe(export_name = "f2k_export_GetFileInformationByHandle")]
pub unsafe extern "system" fn get_file_information_by_handle(file: u32, info: *mut u8) -> u32 {
    if is_console_handle(file) {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    // Errors fail the call; the warnings (a name cut) do not.
    let failed = |status: u32| status & 0xC000_0000 == 0xC000_0000;
    let mut volume = [0u8; 24];
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, into the structure above.
    let status = unsafe {
        nt::NtQueryVolumeInformationFile(
            file,
            &mut io_status,
            volume.as_mut_ptr(),
            24,
            FILE_FS_VOLUME_INFORMATION,
        )
    };
    if failed(status) {
        set_last_nt_error(status);
        return 0;
    }
    let mut all = [0u8; 104];
    let status = query(file, FILE_ALL_INFORMATION, &mut all);
    if failed(status) {
        set_last_nt_error(status);
        return 0;
    }
    let mut out = [0u8; 52];
    out[..4].copy_from_slice(&all[32..36]);
    out[4..28].copy_from_slice(&all[..24]);
    out[28..32].copy_from_slice(&volume[8..12]);
    out[32..36].copy_from_slice(&all[52..56]);
    out[36..40].copy_from_slice(&all[48..52]);
    out[40..44].copy_from_slice(&all[56..60]);
    out[44..48].copy_from_slice(&all[68..72]);
    out[48..52].copy_from_slice(&all[64..68]);
    // SAFETY: the caller's structure.
    unsafe { info.copy_from_nonoverlapping(out.as_ptr(), out.len()) };
    1
}

/// SetEndOfFile: the file ends at its position (FilePositionInformation): its end of file, then its
/// allocation, set there; a console handle is ERROR_INVALID_HANDLE.
#[unsafe(export_name = "f2k_export_SetEndOfFile")]
pub extern "system" fn set_end_of_file(file: u32) -> u32 {
    if is_console_handle(file) {
        set_last_nt_error(STATUS_INVALID_HANDLE);
        return 0;
    }
    let mut position = [0u8; 8];
    let mut status = query(file, FILE_POSITION_INFORMATION, &mut position);
    if nt_success(status) {
        status = set(file, FILE_END_OF_FILE_INFORMATION, &position);
    }
    if nt_success(status) {
        status = set(file, FILE_ALLOCATION_INFORMATION, &position);
    }
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    1
}
