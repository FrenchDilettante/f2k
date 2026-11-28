//! The host tests' file services: one stand-in file, named by [`super::host::HANDLE`] (any other
//! handle names nothing), its calls recorded; the current directory as ntdll keeps it (a DOS path
//! with its trailing separator, open as [`CURRENT_DIRECTORY_HANDLE`]), and rtl's path code over it.

use std::cell::RefCell;
use std::string::String;
use std::vec::Vec;

use super::host::{FAIL_NEXT, HANDLE};
use super::{IoStatus, ObjectAttributes, RelativeName, UnicodeString};

/// The current directory's handle, as the stand-in's paths name it.
pub const CURRENT_DIRECTORY_HANDLE: u32 = 0x48;
use rtl::status::{STATUS_END_OF_FILE, STATUS_INVALID_HANDLE, STATUS_PENDING};

/// A file service call, as the stand-in took it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    /// NtCreateFile or NtOpenFile (or an attributes query): the access, the root, the name,
    /// the share, the disposition (FILE_OPEN for NtOpenFile), the options and the
    /// attributes.
    Open {
        access: u32,
        root: u32,
        name: String,
        share: u32,
        disposition: u32,
        options: u32,
        attributes: u32,
    },
    Read {
        handle: u32,
        length: u32,
        offset: Option<u64>,
    },
    Write {
        handle: u32,
        bytes: Vec<u8>,
        offset: Option<u64>,
    },
    Flush {
        handle: u32,
    },
    Query {
        handle: u32,
        class: u32,
    },
    Set {
        handle: u32,
        class: u32,
        bytes: Vec<u8>,
    },
    Volume {
        handle: u32,
        class: u32,
    },
}

/// The stand-in file: its size and position, its attributes, and what an open answers.
#[derive(Clone, Copy)]
pub struct File {
    pub size: u64,
    pub position: u64,
    pub attributes: u32,
    /// The IO_STATUS_BLOCK Information the next open answers (FILE_OPENED by default).
    pub opened: u32,
}

std::thread_local! {
    pub static CALLS: RefCell<Vec<Call>> = const { RefCell::new(Vec::new()) };
    pub static FILE: RefCell<File> = const {
        RefCell::new(File { size: 0, position: 0, attributes: 0x20, opened: 1 })
    };
    /// The current directory's DOS path (its trailing separator kept), as ntdll keeps it.
    pub static CURRENT_DIRECTORY: RefCell<Vec<u16>> =
        RefCell::new("C:\\".encode_utf16().collect());
    /// A status the stand-in fails with once, after this many of its calls succeed first (a
    /// failure past a call's first service; FAIL_NEXT fails the first).
    pub static FAIL_AFTER: std::cell::Cell<(u32, u32)> = const { std::cell::Cell::new((0, 0)) };
    /// The I/O status the next read or write completes with later: the service answers
    /// STATUS_PENDING, its I/O status block unwritten and the file untouched, as a driver
    /// that pends its IRP does; a wait on the file's handle completes it ([`complete`]).
    pub static PEND_NEXT: std::cell::Cell<Option<IoStatus>> = const { std::cell::Cell::new(None) };
    /// The request left pending: the caller's I/O status block and what completes into it.
    static PENDING: std::cell::Cell<Option<(*mut IoStatus, IoStatus)>> =
        const { std::cell::Cell::new(None) };
}

/// The request PEND_NEXT arranged, left pending into `io_status`: STATUS_PENDING; none when
/// none is arranged.
fn pended(io_status: *mut IoStatus) -> Option<u32> {
    let completion = PEND_NEXT.with(std::cell::Cell::take)?;
    PENDING.with(|pending| pending.set(Some((io_status, completion))));
    Some(STATUS_PENDING)
}

/// The pending request completed, as the I/O manager completes an IRP: its I/O status written
/// into the caller's block. Whether one was pending.
pub fn complete() -> bool {
    let Some((io_status, completion)) = PENDING.with(std::cell::Cell::take) else {
        return false;
    };
    // SAFETY: the block the request was handed, which its caller keeps until it completes
    // (the contract the waits under test keep).
    unsafe { io_status.write(completion) };
    true
}

/// Whether a request is still pending.
pub fn pending() -> bool {
    PENDING.with(|pending| {
        let request = pending.take();
        pending.set(request);
        request.is_some()
    })
}

/// The calls taken since the last look.
pub fn calls() -> Vec<Call> {
    CALLS.with(|calls| std::mem::take(&mut *calls.borrow_mut()))
}

fn record(call: Call) {
    CALLS.with(|calls| calls.borrow_mut().push(call));
}

/// The status the stand-in fails with, once (FAIL_NEXT, else FAIL_AFTER's once its calls have
/// passed).
fn failure() -> Option<u32> {
    let status = FAIL_NEXT.with(|cell| cell.replace(0));
    if status != 0 {
        return Some(status);
    }
    FAIL_AFTER.with(|cell| match cell.get() {
        (_, 0) => None,
        (0, status) => {
            cell.set((0, 0));
            Some(status)
        }
        (passing, status) => {
            cell.set((passing - 1, status));
            None
        }
    })
}

unsafe fn text(string: *const UnicodeString) -> String {
    // SAFETY: the caller's string, its buffer holding its length.
    String::from_utf16_lossy(unsafe { (*string).units() })
}

#[allow(clippy::too_many_arguments)]
unsafe fn opened(
    handle: *mut u32,
    access: u32,
    attributes: *const ObjectAttributes,
    io_status: *mut IoStatus,
    share: u32,
    disposition: u32,
    options: u32,
    file_attributes: u32,
) -> u32 {
    // SAFETY: the caller's attributes and their name.
    let (root, name) = unsafe {
        (
            (*attributes).root_directory,
            text((*attributes).object_name),
        )
    };
    record(Call::Open {
        access,
        root,
        name,
        share,
        disposition,
        options,
        attributes: file_attributes,
    });
    if let Some(status) = failure() {
        return status;
    }
    // SAFETY: the caller's slots.
    unsafe {
        handle.write(HANDLE);
        io_status.write(IoStatus {
            status: 0,
            information: FILE.with(|file| file.borrow().opened),
        });
    }
    0
}

pub unsafe extern "system" fn NtCreateFile(
    handle: *mut u32,
    access: u32,
    attributes: *const ObjectAttributes,
    io_status: *mut IoStatus,
    _allocation: *const u64,
    file_attributes: u32,
    share: u32,
    disposition: u32,
    options: u32,
    _ea: *const u8,
    _ea_length: u32,
) -> u32 {
    // SAFETY: the caller's arguments.
    unsafe {
        opened(
            handle,
            access,
            attributes,
            io_status,
            share,
            disposition,
            options,
            file_attributes,
        )
    }
}

pub unsafe extern "system" fn NtOpenFile(
    handle: *mut u32,
    access: u32,
    attributes: *const ObjectAttributes,
    io_status: *mut IoStatus,
    share: u32,
    options: u32,
) -> u32 {
    // SAFETY: the caller's arguments.
    unsafe { opened(handle, access, attributes, io_status, share, 1, options, 0) }
}

/// The arranged failure, or STATUS_INVALID_HANDLE for a handle naming no file.
fn checked(handle: u32) -> Result<(), u32> {
    if let Some(status) = failure() {
        return Err(status);
    }
    if handle != HANDLE {
        return Err(STATUS_INVALID_HANDLE);
    }
    Ok(())
}

unsafe fn offset_of(offset: *const u64) -> Option<u64> {
    // SAFETY: the caller's offset, when given.
    (!offset.is_null()).then(|| unsafe { offset.read() })
}

pub unsafe extern "system" fn NtReadFile(
    handle: u32,
    _event: u32,
    _routine: usize,
    _context: usize,
    io_status: *mut IoStatus,
    buffer: *mut u8,
    length: u32,
    offset: *const u64,
    _key: *const u32,
) -> u32 {
    // SAFETY: the caller's offset.
    let at = unsafe { offset_of(offset) };
    record(Call::Read {
        handle,
        length,
        offset: at,
    });
    if let Err(status) = checked(handle) {
        return status;
    }
    if let Some(status) = pended(io_status) {
        return status;
    }
    FILE.with(|file| {
        let mut file = file.borrow_mut();
        let start = at.unwrap_or(file.position);
        if length != 0 && start >= file.size {
            return STATUS_END_OF_FILE;
        }
        let moved = (file.size - start).min(length as u64) as u32;
        // SAFETY: the caller's buffer and status block.
        unsafe {
            buffer.write_bytes(0x5A, moved as usize);
            io_status.write(IoStatus {
                status: 0,
                information: moved,
            });
        }
        file.position = start + moved as u64;
        0
    })
}

pub unsafe extern "system" fn NtWriteFile(
    handle: u32,
    _event: u32,
    _routine: usize,
    _context: usize,
    io_status: *mut IoStatus,
    buffer: *const u8,
    length: u32,
    offset: *const u64,
    _key: *const u32,
) -> u32 {
    // SAFETY: the caller's buffer.
    let bytes = unsafe { std::slice::from_raw_parts(buffer, length as usize) }.to_vec();
    // SAFETY: the caller's offset.
    let at = unsafe { offset_of(offset) };
    record(Call::Write {
        handle,
        bytes,
        offset: at,
    });
    if let Err(status) = checked(handle) {
        return status;
    }
    if let Some(status) = pended(io_status) {
        return status;
    }
    FILE.with(|file| {
        let mut file = file.borrow_mut();
        let start = at.unwrap_or(file.position);
        file.position = start + length as u64;
        file.size = file.size.max(file.position);
    });
    // SAFETY: the caller's status block.
    unsafe {
        io_status.write(IoStatus {
            status: 0,
            information: length,
        })
    };
    0
}

pub unsafe extern "system" fn NtFlushBuffersFile(handle: u32, _io_status: *mut IoStatus) -> u32 {
    record(Call::Flush { handle });
    checked(handle).err().unwrap_or(0)
}

/// NtLockFile: granted for a handle the stand-in knows.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn NtLockFile(
    handle: u32,
    _event: u32,
    _routine: usize,
    _context: usize,
    _io_status: *mut IoStatus,
    _offset: *const u64,
    _length: *const u64,
    _key: u32,
    _fail_immediately: u8,
    _exclusive: u8,
) -> u32 {
    checked(handle).err().unwrap_or(0)
}

/// NtUnlockFile: released for a handle the stand-in knows.
pub unsafe extern "system" fn NtUnlockFile(
    handle: u32,
    _io_status: *mut IoStatus,
    _offset: *const u64,
    _length: *const u64,
    _key: u32,
) -> u32 {
    checked(handle).err().unwrap_or(0)
}

pub unsafe extern "system" fn NtQueryInformationFile(
    handle: u32,
    _io_status: *mut IoStatus,
    information: *mut u8,
    length: u32,
    class: u32,
) -> u32 {
    record(Call::Query { handle, class });
    if let Err(status) = checked(handle) {
        return status;
    }
    let file = FILE.with(|file| *file.borrow());
    let mut answer = std::vec![0u8; length as usize];
    match class {
        4 => answer[32..36].copy_from_slice(&file.attributes.to_le_bytes()),
        5 => answer[8..16].copy_from_slice(&file.size.to_le_bytes()),
        14 => answer[..8].copy_from_slice(&file.position.to_le_bytes()),
        18 => {
            answer[32..36].copy_from_slice(&file.attributes.to_le_bytes());
            answer[48..56].copy_from_slice(&file.size.to_le_bytes());
            answer[56..60].copy_from_slice(&1u32.to_le_bytes());
        }
        _ => panic!("the stand-in answers no class {class}"),
    }
    // SAFETY: the caller's buffer of `length` bytes.
    unsafe { information.copy_from_nonoverlapping(answer.as_ptr(), length as usize) };
    0
}

pub unsafe extern "system" fn NtSetInformationFile(
    handle: u32,
    _io_status: *mut IoStatus,
    information: *const u8,
    length: u32,
    class: u32,
) -> u32 {
    // SAFETY: the caller's buffer of `length` bytes.
    let bytes = unsafe { std::slice::from_raw_parts(information, length as usize) }.to_vec();
    record(Call::Set {
        handle,
        class,
        bytes: bytes.clone(),
    });
    if let Err(status) = checked(handle) {
        return status;
    }
    let quad = u64::from_le_bytes(bytes[..8.min(bytes.len())].try_into().unwrap_or([0; 8]));
    FILE.with(|file| match class {
        14 => file.borrow_mut().position = quad,
        20 => file.borrow_mut().size = quad,
        _ => {}
    });
    0
}

pub unsafe extern "system" fn NtQueryDirectoryFile(
    _handle: u32,
    _event: u32,
    _routine: usize,
    _context: usize,
    _io_status: *mut IoStatus,
    _information: *mut u8,
    _length: u32,
    _class: u32,
    _single: u32,
    _name: *const UnicodeString,
    _restart: u32,
) -> u32 {
    failure().unwrap_or(0x8000_0006)
}

pub unsafe extern "system" fn NtQueryAttributesFile(
    attributes: *const ObjectAttributes,
    information: *mut u8,
) -> u32 {
    // SAFETY: the caller's attributes.
    let (root, name) = unsafe {
        (
            (*attributes).root_directory,
            text((*attributes).object_name),
        )
    };
    record(Call::Open {
        access: 0,
        root,
        name,
        share: 0,
        disposition: 1,
        options: 0,
        attributes: 0,
    });
    if let Some(status) = failure() {
        return status;
    }
    let attributes = FILE.with(|file| file.borrow().attributes);
    // SAFETY: the caller's FILE_BASIC_INFORMATION.
    unsafe {
        information.write_bytes(0, 40);
        information
            .add(32)
            .copy_from_nonoverlapping(attributes.to_le_bytes().as_ptr(), 4);
    }
    0
}

pub unsafe extern "system" fn NtQueryFullAttributesFile(
    attributes: *const ObjectAttributes,
    information: *mut u8,
) -> u32 {
    // SAFETY: the caller's attributes.
    let (root, name) = unsafe {
        (
            (*attributes).root_directory,
            text((*attributes).object_name),
        )
    };
    record(Call::Open {
        access: 0,
        root,
        name,
        share: 0,
        disposition: 1,
        options: 0,
        attributes: 0,
    });
    if let Some(status) = failure() {
        return status;
    }
    let file = FILE.with(|file| *file.borrow());
    // SAFETY: the caller's FILE_NETWORK_OPEN_INFORMATION.
    unsafe {
        information.write_bytes(0, 56);
        information
            .add(40)
            .copy_from_nonoverlapping(file.size.to_le_bytes().as_ptr(), 8);
        information
            .add(48)
            .copy_from_nonoverlapping(file.attributes.to_le_bytes().as_ptr(), 4);
    }
    0
}

pub unsafe extern "system" fn NtQueryVolumeInformationFile(
    handle: u32,
    _io_status: *mut IoStatus,
    information: *mut u8,
    length: u32,
    class: u32,
) -> u32 {
    record(Call::Volume { handle, class });
    if let Err(status) = checked(handle) {
        return status;
    }
    assert_eq!((class, length), (4, 8), "the stand-in answers the device");
    // SAFETY: the caller's FILE_FS_DEVICE_INFORMATION: a disk.
    unsafe {
        information.write_bytes(0, 8);
        *information = 7;
    }
    0
}

/// A NUL-terminated string's units.
unsafe fn terminated<'a>(string: *const u16) -> &'a [u16] {
    let mut length = 0;
    // SAFETY: the caller's string, read to its terminator.
    while unsafe { string.add(length).read() } != 0 {
        length += 1;
    }
    // SAFETY: as above.
    unsafe { std::slice::from_raw_parts(string, length) }
}

/// RtlDosPathNameToNtPathName_U over the stand-in's current directory (open), as ntdll runs it:
/// its buffer on the stand-in heap (RtlAllocateHeap's), which the caller frees.
pub unsafe extern "system" fn RtlDosPathNameToNtPathName_U(
    dos: *const u16,
    nt: *mut UnicodeString,
    file_part: *mut *mut u16,
    relative: *mut RelativeName,
) -> u32 {
    const ROOM: usize = 268;
    // SAFETY: the caller's string.
    let path = unsafe { terminated(dos) };
    let current = CURRENT_DIRECTORY.with(|current| current.borrow().clone());
    // SAFETY: the stand-in heap.
    let base = unsafe { super::host::RtlAllocateHeap(0, 0, 2 * ROOM) } as *mut u16;
    // SAFETY: a fresh block of ROOM units.
    let buffer = unsafe { std::slice::from_raw_parts_mut(base, ROOM) };
    let Ok(name) = rtl::path::dos_path_to_nt(path, &current, true, buffer) else {
        // SAFETY: the block just made.
        unsafe { super::host::RtlFreeHeap(0, 0, base as *mut u8) };
        return 0;
    };
    // SAFETY: the caller's structures; the pointers stay inside the block.
    unsafe {
        *nt = UnicodeString {
            length: (2 * name.length) as u16,
            maximum_length: (2 * ROOM) as u16,
            buffer: base,
        };
        if !file_part.is_null() {
            *file_part = name
                .file_part
                .map_or(std::ptr::null_mut(), |at| base.add(at));
        }
        if !relative.is_null() {
            *relative = match name.relative {
                Some(at) => RelativeName {
                    name: UnicodeString {
                        length: (2 * (name.length - at)) as u16,
                        maximum_length: (2 * (name.length - at)) as u16,
                        buffer: base.add(at),
                    },
                    containing_directory: CURRENT_DIRECTORY_HANDLE,
                },
                None => RelativeName {
                    name: UnicodeString {
                        length: 0,
                        maximum_length: 0,
                        buffer: std::ptr::null_mut(),
                    },
                    containing_directory: 0,
                },
            };
        }
    }
    1
}

/// RtlGetFullPathName_U over the stand-in's current directory.
pub unsafe extern "system" fn RtlGetFullPathName_U(
    path: *const u16,
    buffer_length: u32,
    buffer: *mut u16,
    file_part: *mut *mut u16,
) -> u32 {
    // SAFETY: the caller's string.
    let path = unsafe { terminated(path) };
    let current = CURRENT_DIRECTORY.with(|current| current.borrow().clone());
    let mut full = vec![0u16; path.len() + current.len() + 8];
    let Ok((length, part)) = rtl::path::full_path_name(path, &current, &mut full) else {
        return 0;
    };
    if (buffer_length as usize) < 2 * (length + 1) {
        return (2 * (length + 1)) as u32;
    }
    // SAFETY: the caller's buffer holds the path and its terminator.
    unsafe {
        buffer.copy_from_nonoverlapping(full.as_ptr(), length + 1);
        if !file_part.is_null() {
            *file_part = part.map_or(std::ptr::null_mut(), |at| buffer.add(at));
        }
    }
    (2 * length) as u32
}

std::thread_local! {
    /// The full paths that exist, for RtlDoesFileExists_U (compared without regard to case).
    pub static EXISTING_PATHS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// The paths RtlDoesFileExists_U was asked about, in order.
    pub static EXISTENCE_ASKED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// RtlDoesFileExists_U: whether the path, made full over the stand-in's current directory, is
/// one of [`EXISTING_PATHS`]; the path asked kept in [`EXISTENCE_ASKED`].
pub unsafe extern "system" fn RtlDoesFileExists_U(path: *const u16) -> u8 {
    // SAFETY: the caller's string.
    let path = unsafe { terminated(path) };
    let current = CURRENT_DIRECTORY.with(|current| current.borrow().clone());
    let mut full = [0u16; 1040];
    let Ok((length, _)) = rtl::path::full_path_name(path, &current, &mut full) else {
        return 0;
    };
    let full = String::from_utf16(&full[..length]).unwrap();
    EXISTENCE_ASKED.with(|asked| asked.borrow_mut().push(String::from_utf16(path).unwrap()));
    u8::from(EXISTING_PATHS.with(|existing| {
        existing
            .borrow()
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&full))
    }))
}

/// RtlDetermineDosPathNameType_U (rtl::path, as ntdll runs it).
pub unsafe extern "system" fn RtlDetermineDosPathNameType_U(path: *const u16) -> u32 {
    use rtl::path::PathType;
    // SAFETY: the caller's string.
    match rtl::path::path_type(unsafe { terminated(path) }) {
        PathType::UncAbsolute => 1,
        PathType::DriveAbsolute => 2,
        PathType::DriveRelative => 3,
        PathType::Rooted => 4,
        PathType::Relative => 5,
        PathType::LocalDevice => 6,
        PathType::RootLocalDevice => 7,
    }
}

/// RtlGetCurrentDirectory_U, over the stand-in's current directory.
pub unsafe extern "system" fn RtlGetCurrentDirectory_U(
    buffer_length: u32,
    buffer: *mut u16,
) -> u32 {
    CURRENT_DIRECTORY.with(|current| {
        let current = current.borrow();
        let mut length = current.len();
        if length > 3 && current[length - 1] == u16::from(b'\\') {
            length -= 1;
        }
        if (buffer_length as usize) < 2 * (length + 1) {
            return (2 * (length + 1)) as u32;
        }
        // SAFETY: the caller's buffer holds the path and its terminator.
        unsafe {
            buffer.copy_from_nonoverlapping(current.as_ptr(), length);
            buffer.add(length).write(0);
        }
        (2 * length) as u32
    })
}

/// RtlSetCurrentDirectory_U, the stand-in's: made absolute and folded as ntdll does
/// (rtl::path), the open standing in by FAIL_NEXT.
pub unsafe extern "system" fn RtlSetCurrentDirectory_U(path: *const UnicodeString) -> u32 {
    if let Some(status) = failure() {
        return status;
    }
    // SAFETY: the caller's string.
    let units = unsafe { (*path).units() };
    let mut out = [0u16; 261];
    let current = CURRENT_DIRECTORY.with(|current| current.borrow().clone());
    match rtl::path::full_path_name(units, &current, &mut out[..260]) {
        Ok((mut length, _)) => {
            if out[length - 1] != u16::from(b'\\') {
                out[length] = u16::from(b'\\');
                length += 1;
            }
            CURRENT_DIRECTORY.with(|current| *current.borrow_mut() = out[..length].to_vec());
            0
        }
        Err(rtl::path::PathError::Empty) => rtl::status::STATUS_OBJECT_NAME_INVALID,
        Err(rtl::path::PathError::TooLong) => rtl::status::STATUS_NAME_TOO_LONG,
    }
}

/// The critical sections a find handle's lock takes (one thread: nothing to wait for).
pub unsafe extern "system" fn RtlEnterCriticalSection(_section: *mut u8) -> u32 {
    0
}
pub unsafe extern "system" fn RtlLeaveCriticalSection(_section: *mut u8) -> u32 {
    0
}
pub unsafe extern "system" fn RtlDeleteCriticalSection(_section: *mut u8) -> u32 {
    0
}
