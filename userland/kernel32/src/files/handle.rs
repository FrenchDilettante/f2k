//! The calls on a file handle: CreateFileA (CreateFileW's work over NtCreateFile), ReadFile and
//! WriteFile (NtReadFile, NtWriteFile; a console handle's bytes go to the console), SetFilePointer,
//! FlushFileBuffers, GetFileType, the size, times and identity of an open file, SetFileTime and
//! SetEndOfFile — as Windows 2000's kernel32 makes them of the information classes.

use core::mem::offset_of;

use rtl::status::nt_success;

use super::*;
use crate::base::{is_console_handle, set_last_error, set_last_nt_error, standard_handle};
use crate::console;
use crate::edge::{InBuf, OutBuf};
use crate::error::{answer, bool_answer};
use crate::nt::IoStatus;
use crate::ntcall::{Destination, Source, Transfer};

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

/// CreateFileW's work, the W form every create shares (CreateFileA, CopyFileA): a console name
/// (CONIN$, CONOUT$, CON) opened at the console server ([`console::open_console`], as Windows
/// 2000's CreateFile hands it to OpenConsoleW); otherwise the disposition
/// mapped (TRUNCATE_EXISTING asks GENERIC_WRITE), the path made an NT one, the flags mapped to
/// create options (no backup semantics: no directory; delete-on-close: DELETE access too), and
/// NtCreateFile asked for the access with SYNCHRONIZE and FILE_READ_ATTRIBUTES. On success the
/// last error is ERROR_ALREADY_EXISTS when CREATE_ALWAYS or OPEN_ALWAYS found the file, cleared
/// otherwise, and TRUNCATE_EXISTING cuts the file (FileAllocationInformation). A name already
/// taken under CREATE_NEW is ERROR_FILE_EXISTS; any other failure the status's error.
pub fn create_file_w(
    name: &Wide,
    access: u32,
    share: u32,
    security: Option<In<'_, SecurityAttributes>>,
    disposition: u32,
    flags: u32,
) -> Result<u32, Failure> {
    if let Some(output) = console::console_name(name.text(), access) {
        return console::open_console(output, access, inherits(security), share);
    }
    let create = match disposition {
        CREATE_NEW => FILE_CREATE,
        CREATE_ALWAYS => FILE_OVERWRITE_IF,
        OPEN_EXISTING => FILE_OPEN,
        OPEN_ALWAYS => FILE_OPEN_IF,
        TRUNCATE_EXISTING if access & GENERIC_WRITE != 0 => FILE_OPEN,
        _ => return Err(Failure::Status(STATUS_INVALID_PARAMETER)),
    };
    let path = NtPath::of(name.terminated()).ok_or(Failure::Error(ERROR_PATH_NOT_FOUND))?;
    let mut attributes = path.attributes(inherits(security));
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
    let created = ntcall::create_file(
        access | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
        &attributes,
        flags & (FILE_ATTRIBUTE_VALID_FLAGS & !FILE_ATTRIBUTE_DIRECTORY),
        share,
        create,
        options,
    );
    drop(path);
    let created = created.map_err(|status| {
        if status == STATUS_OBJECT_NAME_COLLISION {
            // The status's error first (ntdll keeps the status as the thread's last), then
            // kernel32's own over it.
            set_last_nt_error(status);
            Failure::Error(ERROR_FILE_EXISTS)
        } else {
            Failure::Status(status)
        }
    })?;
    let found = (disposition == CREATE_ALWAYS && created.information == FILE_OVERWRITTEN)
        || (disposition == OPEN_ALWAYS && created.information == FILE_OPENED);
    set_last_error(if found { ERROR_ALREADY_EXISTS } else { 0 });
    if disposition == TRUNCATE_EXISTING {
        let status = set(
            created.handle,
            FILE_ALLOCATION_INFORMATION,
            &0u64.to_le_bytes(),
        );
        if !nt_success(status) {
            close(created.handle);
            return Err(Failure::Status(status));
        }
    }
    Ok(created.handle)
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
    // SAFETY: the caller's string (null: the empty one) and structure, when given (the contract).
    let (name, security) = unsafe { (InStr::optional(name), In::optional(security)) };
    let handle = widen(name.as_ref())
        .and_then(|name| create_file_w(&name, access, share, security, disposition, flags));
    answer(handle, INVALID_HANDLE_VALUE)
}

/// CreateFileW: the name copied ([`wide`]), then its work ([`create_file_w`]); the template file is
/// not consulted.
///
/// # Safety
///
/// `name` is a NUL-terminated UTF-16 string; `security` null or a SECURITY_ATTRIBUTES.
#[unsafe(export_name = "f2k_export_CreateFileW")]
pub unsafe extern "system" fn create_file_w_export(
    name: *const u16,
    access: u32,
    share: u32,
    security: *const SecurityAttributes,
    disposition: u32,
    flags: u32,
    _template: u32,
) -> u32 {
    // SAFETY: the caller's string and structure, when given (the contract).
    let (name, security) = unsafe { (InWStr::new(name), In::optional(security)) };
    let handle = wide(&name)
        .and_then(|name| create_file_w(&name, access, share, security, disposition, flags));
    answer(handle, INVALID_HANDLE_VALUE)
}

/// An OVERLAPPED, as the caller passes it: its I/O status (Internal, InternalHigh), its offset and
/// its event.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Overlapped {
    pub internal: u32,
    pub internal_high: u32,
    pub offset: u32,
    pub offset_high: u32,
    pub event: u32,
}

/// What a synchronous read or write reports: TRUE with the count, or FALSE with the status's error
/// (the count of a warning kept).
fn transferred(
    status: u32,
    io_status: &IoStatus,
    count: Option<&mut Out<'_, u32>>,
) -> Result<(), Failure> {
    if nt_success(status) {
        put(count, io_status.information);
        return Ok(());
    }
    if status & 0xC000_0000 == 0x8000_0000 {
        put(count, io_status.information);
    }
    Err(Failure::Status(status))
}

/// An overlapped read or write's answer, Windows 2000's: started at the OVERLAPPED's offset with
/// its event, its I/O status there; TRUE with the count once complete (every F2K file completes at
/// once), FALSE with the status's error otherwise (end of file: a count of zero).
fn overlapped_transfer(
    mut overlapped: Out<'_, Overlapped>,
    mut count: Option<&mut Out<'_, u32>>,
    start: impl FnOnce(Transfer<'_>, &mut Out<'_, IoStatus>) -> u32,
) -> Result<(), Failure> {
    const IO_STATUS: usize = offset_of!(Overlapped, internal);
    overlapped.part::<u32>(IO_STATUS).set(STATUS_PENDING);
    let asked = overlapped.get();
    let offset = u64::from(asked.offset) | u64::from(asked.offset_high) << 32;
    let context = if asked.event & 1 != 0 {
        0
    } else {
        overlapped.as_ptr() as usize
    };
    let transfer = Transfer::Started {
        event: asked.event,
        context,
        offset: &offset,
    };
    let status = start(transfer, &mut overlapped.part::<IoStatus>(IO_STATUS));
    if nt_success(status) && status != STATUS_PENDING {
        put(count.as_deref_mut(), overlapped.get().internal_high);
        return Ok(());
    }
    if status == STATUS_END_OF_FILE {
        put(count, 0);
    }
    Err(Failure::Status(status))
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
    // SAFETY: the caller's buffer, and its dword and OVERLAPPED when given (the contract).
    let (buffer, read, overlapped) = unsafe {
        (
            OutBuf::new(buffer, count as usize),
            Out::optional(read),
            Out::optional(overlapped),
        )
    };
    read_from(file, buffer, read, overlapped)
}

/// ReadFile's work.
fn read_from(
    file: u32,
    buffer: OutBuf<'_, u8>,
    mut read: Option<Out<'_, u32>>,
    overlapped: Option<Out<'_, Overlapped>>,
) -> u32 {
    put(read.as_mut(), 0);
    let file = standard_handle(file);
    if is_console_handle(file) {
        return console::read_console(file, buffer, read);
    }
    if let Some(overlapped) = overlapped {
        let buffer = Destination::from(buffer);
        return bool_answer(overlapped_transfer(
            overlapped,
            read.as_mut(),
            |transfer, io_status| ntcall::read_file(file, transfer, io_status, buffer),
        ));
    }
    let mut io_status = IoStatus::default();
    let status = ntcall::read_file(
        file,
        Transfer::AtPosition,
        &mut Out::from(&mut io_status),
        Destination::from(buffer),
    );
    if status == STATUS_END_OF_FILE {
        put(read.as_mut(), 0);
        return 1;
    }
    bool_answer(transferred(status, &io_status, read.as_mut()))
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
    // SAFETY: the caller's buffer, and its dword and OVERLAPPED when given (the contract).
    let (buffer, written, overlapped) = unsafe {
        (
            InBuf::new(buffer, count as usize),
            Out::optional(written),
            Out::optional(overlapped),
        )
    };
    write_to(file, buffer, written, overlapped)
}

/// WriteFile's work.
fn write_to(
    file: u32,
    buffer: InBuf<'_, u8>,
    mut written: Option<Out<'_, u32>>,
    overlapped: Option<Out<'_, Overlapped>>,
) -> u32 {
    put(written.as_mut(), 0);
    let file = standard_handle(file);
    if is_console_handle(file) {
        return console::write_console(
            file,
            buffer.as_ptr() as usize,
            buffer.len() as u32,
            written,
            overlapped.is_some(),
            false,
        );
    }
    if let Some(overlapped) = overlapped {
        let buffer = Source::from(buffer);
        return bool_answer(overlapped_transfer(
            overlapped,
            written.as_mut(),
            |transfer, io_status| ntcall::write_file(file, transfer, io_status, buffer),
        ));
    }
    let mut io_status = IoStatus::default();
    let status = ntcall::write_file(
        file,
        Transfer::AtPosition,
        &mut Out::from(&mut io_status),
        Source::from(buffer),
    );
    bool_answer(transferred(status, &io_status, written.as_mut()))
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
    // SAFETY: the caller's high dword, when given (the contract).
    let high = unsafe { Out::optional(high) };
    answer(
        file_pointer(file, low, high, method),
        INVALID_SET_FILE_POINTER,
    )
}

/// SetFilePointer's work.
fn file_pointer(
    file: u32,
    low: u32,
    mut high: Option<Out<'_, i32>>,
    method: u32,
) -> Result<u32, Failure> {
    if is_console_handle(file) {
        return Err(Failure::Status(STATUS_INVALID_HANDLE));
    }
    let distance = match &high {
        None => i64::from(low as i32),
        Some(high) => (i64::from(high.get()) << 32) | i64::from(low),
    };
    let target = match method {
        FILE_BEGIN => distance,
        FILE_CURRENT => {
            let mut position = [0u8; 8];
            checked(query(file, FILE_POSITION_INFORMATION, &mut position))?;
            (quad(&position, 0) as i64).wrapping_add(distance)
        }
        FILE_END => {
            let mut standard = [0u8; 24];
            checked(query(file, FILE_STANDARD_INFORMATION, &mut standard))?;
            (quad(&standard, 8) as i64).wrapping_add(distance)
        }
        _ => return Err(Failure::Error(ERROR_INVALID_PARAMETER)),
    };
    if target < 0 {
        return Err(Failure::Error(ERROR_NEGATIVE_SEEK));
    }
    if high.is_none() && (target >> 32) & 0x7FFF_FFFF != 0 {
        return Err(Failure::Error(ERROR_INVALID_PARAMETER));
    }
    let status = set(
        file,
        FILE_POSITION_INFORMATION,
        &(target as u64).to_le_bytes(),
    );
    if !nt_success(status) {
        set_last_nt_error(status);
        put(high.as_mut(), -1);
        return Ok(INVALID_SET_FILE_POINTER);
    }
    put(high.as_mut(), (target >> 32) as i32);
    if target as u32 == INVALID_SET_FILE_POINTER {
        set_last_error(0);
    }
    Ok(target as u32)
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
    bool_answer(ntcall::flush_buffers_file(file).map_err(Failure::Status))
}

/// GetFileType: a console handle naming a console object is a character device
/// (VerifyConsoleIoHandle, as Windows 2000's asks the console; one naming none is FILE_TYPE_UNKNOWN
/// with ERROR_INVALID_HANDLE); any other handle's device type (FileFsDeviceInformation) decides — a
/// disk's file FILE_TYPE_DISK. A null handle, and one the device query fails for, is
/// FILE_TYPE_UNKNOWN with the error.
#[unsafe(export_name = "f2k_export_GetFileType")]
pub extern "system" fn get_file_type(file: u32) -> u32 {
    answer(file_type(file), FILE_TYPE_UNKNOWN)
}

/// GetFileType's work.
fn file_type(file: u32) -> Result<u32, Failure> {
    let file = standard_handle(file);
    if is_console_handle(file) {
        if console::verify_console_io_handle(file) {
            return Ok(FILE_TYPE_CHAR);
        }
        return Err(Failure::Error(ERROR_INVALID_HANDLE));
    }
    if file == 0 {
        return Err(Failure::Error(ERROR_INVALID_HANDLE));
    }
    let mut device = [0u8; 8];
    checked(query_volume(file, FILE_FS_DEVICE_INFORMATION, &mut device))?;
    Ok(match word(&device, 0) {
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
    })
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
    // SAFETY: the caller's high dword, when given (the contract).
    let high = unsafe { Out::optional(high) };
    answer(file_size(file, high), 0xFFFF_FFFF)
}

/// GetFileSize's work.
fn file_size(file: u32, mut high: Option<Out<'_, u32>>) -> Result<u32, Failure> {
    let mut standard = [0u8; 24];
    checked(query(file, FILE_STANDARD_INFORMATION, &mut standard))?;
    put(high.as_mut(), word(&standard, 12));
    let low = word(&standard, 8);
    if low == 0xFFFF_FFFF {
        set_last_error(0);
    }
    Ok(low)
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
    // SAFETY: the caller's FILETIMEs, when given (the contract).
    let times = unsafe {
        [
            Out::optional(created),
            Out::optional(accessed),
            Out::optional(written),
        ]
    };
    bool_answer(file_time(file, times))
}

/// GetFileTime's work.
fn file_time(file: u32, mut times: [Option<Out<'_, u64>>; 3]) -> Result<(), Failure> {
    let mut basic = [0u8; 40];
    checked(query(file, FILE_BASIC_INFORMATION, &mut basic))?;
    for (at, time) in times.iter_mut().enumerate() {
        put(time.as_mut(), quad(&basic, 8 * at));
    }
    Ok(())
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
    // SAFETY: the caller's FILETIMEs, when given (the contract).
    let times = unsafe {
        [
            In::optional(created),
            In::optional(accessed),
            In::optional(written),
        ]
    };
    bool_answer(set_times(file, times))
}

/// SetFileTime's work.
fn set_times(file: u32, times: [Option<In<'_, u64>>; 3]) -> Result<(), Failure> {
    let mut basic = [0u8; 40];
    for (at, time) in times.iter().enumerate() {
        if let Some(time) = time {
            basic[8 * at..8 * at + 8].copy_from_slice(&time.read().to_le_bytes());
        }
    }
    checked(set(file, FILE_BASIC_INFORMATION, &basic))
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
    // SAFETY: the caller's BY_HANDLE_FILE_INFORMATION (the contract).
    let info = unsafe { OutBuf::new(info, BY_HANDLE_FILE_INFORMATION) };
    bool_answer(file_information(file, info))
}

/// The size of a BY_HANDLE_FILE_INFORMATION.
const BY_HANDLE_FILE_INFORMATION: usize = 52;

/// GetFileInformationByHandle's work.
fn file_information(file: u32, mut info: OutBuf<'_, u8>) -> Result<(), Failure> {
    if is_console_handle(file) {
        return Err(Failure::Error(ERROR_INVALID_HANDLE));
    }
    let mut volume = [0u8; 24];
    unless_error(query_volume(file, FILE_FS_VOLUME_INFORMATION, &mut volume))?;
    let mut all = [0u8; 104];
    unless_error(query(file, FILE_ALL_INFORMATION, &mut all))?;
    let mut out = [0u8; BY_HANDLE_FILE_INFORMATION];
    out[..4].copy_from_slice(&all[32..36]);
    out[4..28].copy_from_slice(&all[..24]);
    out[28..32].copy_from_slice(&volume[8..12]);
    out[32..36].copy_from_slice(&all[52..56]);
    out[36..40].copy_from_slice(&all[48..52]);
    out[40..44].copy_from_slice(&all[56..60]);
    out[44..48].copy_from_slice(&all[68..72]);
    out[48..52].copy_from_slice(&all[64..68]);
    info.put(&out);
    Ok(())
}

/// SetEndOfFile: the file ends at its position (FilePositionInformation): its end of file, then its
/// allocation, set there; a console handle is ERROR_INVALID_HANDLE.
#[unsafe(export_name = "f2k_export_SetEndOfFile")]
pub extern "system" fn set_end_of_file(file: u32) -> u32 {
    bool_answer(end_of_file(file))
}

/// SetEndOfFile's work.
fn end_of_file(file: u32) -> Result<(), Failure> {
    if is_console_handle(file) {
        return Err(Failure::Status(STATUS_INVALID_HANDLE));
    }
    let mut position = [0u8; 8];
    checked(query(file, FILE_POSITION_INFORMATION, &mut position))?;
    checked(set(file, FILE_END_OF_FILE_INFORMATION, &position))?;
    checked(set(file, FILE_ALLOCATION_INFORMATION, &position))
}
