//! The descriptor layer: the C runtime's file descriptors over Win32 handles, and their text mode.
//!
//! A table of 2048 descriptors, each a handle and its flags. Descriptors 0, 1 and 2 are the
//! standard handles when the DLL is loaded (one that is missing still counts as open, a device), so
//! the first a program opens is 3. As fd's capture pins it:
//!
//! - `_open` opens a file by name on the lowest free descriptor, as MSDN documents its flags
//!   ([`open_plan`]); spawn's crtfds capture pins its descriptors and the flags a child is handed:
//!   0x01 for a file read in binary, 0xA1 for one written appending in text, none for one opened
//!   `_O_NOINHERIT`.
//! - `_open_osfhandle` takes the lowest free descriptor, text mode only with `_O_TEXT` (so its
//!   flags 0 are binary), and refuses a handle whose type is unknown (EBADF); a read-only flag does
//!   not stop writes.
//! - A descriptor that is not open, or out of range, is EBADF (`_get_osfhandle(-1)`, `_dup(77)`,
//!   `_dup2(fd, 5000)`).
//! - `_close` closes the handle too; `_dup` duplicates it (the file position shared) onto the
//!   lowest free descriptor, `_dup2` onto the one named, closing what it held. In a console
//!   program, descriptors 0 to 2 keep the standard handles in step (SetStdHandle). Descriptors 1
//!   and 2 sharing one handle, closing one leaves it open for the other.
//! - Text mode writes each LF as CR LF (`_write` answers the caller's bytes, `_tell` sees the
//!   file's); it reads CR LF as LF and stops at Ctrl-Z (a file's end, for a file).
//! - `_setmode` answers the previous mode (`_O_TEXT` or `_O_BINARY`); another mode is EINVAL.
//! - A child the _spawn family starts is handed the open descriptors (but those opened
//!   `_O_NOINHERIT`) in STARTUPINFO's C runtime block ([`inheritance_length`]); its start-up takes
//!   them, then the standard handles for those of 0 to 2 it was not handed.

use crate::data::Global;
use crate::imports;
use crate::thread::{self, set_dos_error, set_errno, Locked, EBADF, EINVAL, EMFILE, ENOSPC};

/// The descriptors the table holds.
pub const DESCRIPTORS: usize = 2048;

/// A descriptor's flags.
const FOPEN: u8 = 0x01;
const FEOF: u8 = 0x02;
const FPIPE: u8 = 0x08;
const FNOINHERIT: u8 = 0x10;
const FAPPEND: u8 = 0x20;
const FDEV: u8 = 0x40;
const FTEXT: u8 = 0x80;

/// fcntl.h's flags `_open`, `_open_osfhandle` and `_setmode` take: the access (the low two bits),
/// appending, the creation's and the translation's.
pub const O_RDONLY: i32 = 0x0000;
pub const O_WRONLY: i32 = 0x0001;
pub const O_RDWR: i32 = 0x0002;
const O_ACCESS: i32 = 0x0003;
pub const O_APPEND: i32 = 0x0008;
pub const O_NOINHERIT: i32 = 0x0080;
pub const O_CREAT: i32 = 0x0100;
pub const O_TRUNC: i32 = 0x0200;
pub const O_EXCL: i32 = 0x0400;
pub const O_TEXT: i32 = 0x4000;
pub const O_BINARY: i32 = 0x8000;

/// sys/stat.h's write permission: a file `_open` creates without it is read-only.
pub const S_IWRITE: i32 = 0x0080;

/// CreateFileA's values `_open` asks with: the access, the sharing (`_SH_DENYNO`: both ways), the
/// dispositions and the attributes.
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ_WRITE: u32 = 0x3;
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;
const FILE_ATTRIBUTE_READONLY: u32 = 0x01;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_HANDLE_VALUE: usize = usize::MAX;

/// GetFileType's answers.
const FILE_TYPE_UNKNOWN: u32 = 0;
const FILE_TYPE_CHAR: u32 = 2;
const FILE_TYPE_PIPE: u32 = 3;

/// The standard handles' ids, descriptors 0 to 2's.
const STANDARD: [u32; 3] = [-10i32 as u32, -11i32 as u32, -12i32 as u32];

/// Win32 errors the layer tells apart.
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_BROKEN_PIPE: u32 = 109;

/// Ctrl-Z: a text file's end.
const CTRL_Z: u8 = 0x1A;

/// One descriptor.
#[derive(Clone, Copy)]
struct Descriptor {
    handle: usize,
    flags: u8,
    /// A pipe's or device's byte read ahead by a CR at a read's end (none: 0x100).
    ahead: u16,
}

const CLOSED: Descriptor = Descriptor {
    handle: usize::MAX,
    flags: 0,
    ahead: 0x100,
};

static TABLE: Global<[Descriptor; DESCRIPTORS]> = Global::new([CLOSED; DESCRIPTORS]);

/// __set_app_type's value: 1 for a console program (whose descriptors 0 to 2 keep the standard
/// handles in step), 2 for a GUI one, 0 before the program says.
pub static APP_TYPE: Global<i32> = Global::new(0);

fn table() -> &'static mut [Descriptor; DESCRIPTORS] {
    // SAFETY: the process's descriptors; callers hold the C runtime's lock where they change them.
    unsafe { &mut *TABLE.get() }
}

/// The open descriptor `fd`'s entry, or none (errno EBADF).
fn open(fd: i32) -> Option<&'static mut Descriptor> {
    let entry = usize::try_from(fd)
        .ok()
        .and_then(|fd| table().get_mut(fd))
        .filter(|entry| entry.flags & FOPEN != 0);
    if entry.is_none() {
        set_errno(EBADF);
        thread::set_doserrno(0);
    }
    entry
}

/// The flags a handle's type gives a descriptor.
fn type_flags(kind: u32) -> u8 {
    match kind {
        FILE_TYPE_CHAR => FDEV,
        FILE_TYPE_PIPE => FPIPE,
        _ => 0,
    }
}

/// The descriptors a parent hands its child, as the C runtime passes them in STARTUPINFO's
/// cbReserved2 and lpReserved2 (MSDN: "reserved for use by the C run-time"): a dword, the count;
/// then each descriptor's flags, a byte (zero for one not handed on); then each one's handle, a
/// dword (INVALID_HANDLE_VALUE for none). Its length for `count` descriptors.
pub const fn inheritance_length(count: usize) -> usize {
    4 + 5 * count
}

/// The block for `descriptors` (each its flags and handle) into `out`, of its
/// [`inheritance_length`].
pub fn encode_inheritance(descriptors: impl ExactSizeIterator<Item = (u8, u32)>, out: &mut [u8]) {
    let count = descriptors.len();
    out[..4].copy_from_slice(&(count as u32).to_le_bytes());
    for (at, (flags, handle)) in descriptors.enumerate() {
        out[4 + at] = flags;
        let handle_at = 4 + count + 4 * at;
        out[handle_at..handle_at + 4].copy_from_slice(&handle.to_le_bytes());
    }
}

/// The descriptors a block hands on, each its flags and handle, in descriptor order: as many as
/// its count says and its length holds.
pub fn decode_inheritance(block: &[u8]) -> impl Iterator<Item = (u8, u32)> + '_ {
    let count = block
        .get(..4)
        .map_or(0, |count| {
            u32::from_le_bytes(count.try_into().unwrap()) as usize
        })
        .min(block.len().saturating_sub(4) / 5);
    (0..count).map(move |at| {
        let handle_at = 4 + count + 4 * at;
        let handle = u32::from_le_bytes(block[handle_at..handle_at + 4].try_into().unwrap());
        (block[4 + at], handle)
    })
}

/// The descriptors a child inherits (see [`inheritance_length`]): up to the last one open, each
/// open one's flags and handle unless it was opened `_O_NOINHERIT` (then none, as a closed one).
/// The caller holds the C runtime's lock.
pub fn inheritance_count() -> usize {
    table()
        .iter()
        .rposition(|entry| entry.flags & FOPEN != 0)
        .map_or(0, |last| last + 1)
}

/// The block for the descriptors a child inherits into `out`, of the [`inheritance_length`] of
/// [`inheritance_count`]'s count. The caller holds the C runtime's lock.
pub fn write_inheritance(out: &mut [u8]) {
    let descriptors = table()[..inheritance_count()].iter().map(|entry| {
        if entry.flags & FOPEN != 0 && entry.flags & FNOINHERIT == 0 {
            (entry.flags, entry.handle as u32)
        } else {
            (0, u32::MAX)
        }
    });
    encode_inheritance(descriptors, out);
}

/// The descriptors the parent handed on (STARTUPINFO's C runtime block): each open one whose
/// handle is valid and of a known type takes its descriptor, flags and all.
fn take_inherited() {
    let mut info = imports::StartupInfoA::new();
    // SAFETY: kernel32's export, into the structure above.
    unsafe { imports::GetStartupInfoA(&mut info) };
    if info.reserved2.is_null() || info.reserved2_length < 4 {
        return;
    }
    // SAFETY: the block the parent's C runtime made, cbReserved2 bytes at lpReserved2 (kernel32
    // copied it into the process parameters, for the process's whole life).
    let block =
        unsafe { core::slice::from_raw_parts(info.reserved2, usize::from(info.reserved2_length)) };
    for (fd, (flags, handle)) in decode_inheritance(block).enumerate().take(DESCRIPTORS) {
        let handle = handle as usize;
        if flags & FOPEN == 0 || handle == 0 || handle as u32 == u32::MAX {
            continue;
        }
        // SAFETY: kernel32's export.
        if unsafe { imports::GetFileType(handle) } == FILE_TYPE_UNKNOWN {
            continue;
        }
        table()[fd] = Descriptor {
            handle,
            flags,
            ahead: 0x100,
        };
    }
}

/// The DLL's process attach: the descriptors the parent handed on, then those of 0 to 2 it did
/// not over the standard handles, in text mode.
pub fn initialize() {
    take_inherited();
    for (fd, &which) in STANDARD.iter().enumerate() {
        if table()[fd].flags & FOPEN != 0 {
            continue;
        }
        // SAFETY: kernel32's exports.
        let (handle, kind) = unsafe {
            let handle = imports::GetStdHandle(which);
            let valid = handle != 0 && handle != usize::MAX;
            (
                handle,
                if valid {
                    imports::GetFileType(handle)
                } else {
                    FILE_TYPE_UNKNOWN
                },
            )
        };
        table()[fd] = Descriptor {
            handle,
            flags: FOPEN
                | FTEXT
                | if kind == FILE_TYPE_UNKNOWN {
                    FDEV
                } else {
                    type_flags(kind)
                },
            ahead: 0x100,
        };
    }
}

/// Whether `fd` is a character device (the console).
pub fn is_device(fd: i32) -> bool {
    usize::try_from(fd)
        .ok()
        .and_then(|fd| table().get(fd))
        .is_some_and(|entry| entry.flags & (FOPEN | FDEV) == FOPEN | FDEV)
}

/// The lowest free descriptor, or none (errno EMFILE).
fn free_descriptor() -> Option<usize> {
    let fd = table().iter().position(|entry| entry.flags & FOPEN == 0);
    if fd.is_none() {
        set_errno(EMFILE);
        thread::set_doserrno(0);
    }
    fd
}

/// Descriptor `fd` given `handle`: a standard one's handle follows in a console program.
fn set_handle(fd: usize, handle: usize) {
    table()[fd].handle = handle;
    if fd < 3 && APP_TYPE.read() == 1 {
        // SAFETY: kernel32's export.
        unsafe { imports::SetStdHandle(STANDARD[fd], handle) };
    }
}

/// Descriptor `fd` freed: a standard one's handle cleared in a console program.
fn free(fd: usize) {
    table()[fd] = CLOSED;
    if fd < 3 && APP_TYPE.read() == 1 {
        // SAFETY: kernel32's export.
        unsafe { imports::SetStdHandle(STANDARD[fd], 0) };
    }
}

/// _open_osfhandle: a descriptor over `handle`, its mode from `flags` (`_O_TEXT`, `_O_APPEND`,
/// `_O_NOINHERIT`); -1 with EBADF for a handle of unknown type, EMFILE when none is free.
#[unsafe(export_name = "f2k_export__open_osfhandle")]
pub extern "C" fn open_osfhandle(handle: usize, flags: i32) -> i32 {
    // SAFETY: kernel32's export.
    let kind = unsafe { imports::GetFileType(handle) };
    if kind == FILE_TYPE_UNKNOWN {
        // SAFETY: kernel32's export.
        let error = unsafe { imports::GetLastError() };
        set_errno(EBADF);
        thread::set_doserrno(error);
        return -1;
    }
    let _lock = Locked::take();
    let Some(fd) = free_descriptor() else {
        return -1;
    };
    let mut mode = FOPEN | type_flags(kind);
    if flags & O_TEXT != 0 {
        mode |= FTEXT;
    }
    if flags & O_APPEND != 0 {
        mode |= FAPPEND;
    }
    if flags & O_NOINHERIT != 0 {
        mode |= FNOINHERIT;
    }
    table()[fd] = Descriptor {
        handle: usize::MAX,
        flags: mode,
        ahead: 0x100,
    };
    set_handle(fd, handle);
    fd as i32
}

/// What `_open` asks CreateFileA for and the descriptor it makes: the access, the disposition, the
/// new file's attributes, whether the handle is inheritable, and the descriptor's mode flags (its
/// type's are the handle's, added once it is open).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OpenPlan {
    access: u32,
    disposition: u32,
    attributes: u32,
    inherit: bool,
    mode: u8,
}

/// `_open`'s plan for `oflag`, `pmode` (looked at only with `_O_CREAT`) and `_fmode`'s value
/// `fmode`, as MSDN's `_open` documents the flags: the access mode `_O_RDONLY`, `_O_WRONLY` or
/// `_O_RDWR` (any other is none: EINVAL); `_O_CREAT` creates a missing file (failing on an
/// existing one with `_O_EXCL`, truncating it with `_O_TRUNC`), read-only when `pmode` lacks
/// `_S_IWRITE`; `_O_TRUNC` alone truncates an existing file; `_O_APPEND` writes at the end;
/// `_O_BINARY` or `_O_TEXT` sets the translation (`_O_BINARY` deciding when both are given), else
/// `_fmode` does (text unless it is `_O_BINARY`); `_O_NOINHERIT` keeps the handle and the
/// descriptor from a child.
fn open_plan(oflag: i32, pmode: i32, fmode: i32) -> Option<OpenPlan> {
    let access = match oflag & O_ACCESS {
        O_RDONLY => GENERIC_READ,
        O_WRONLY => GENERIC_WRITE,
        O_RDWR => GENERIC_READ | GENERIC_WRITE,
        _ => return None,
    };
    let disposition = match (
        oflag & O_CREAT != 0,
        oflag & O_EXCL != 0,
        oflag & O_TRUNC != 0,
    ) {
        (true, true, _) => CREATE_NEW,
        (true, false, true) => CREATE_ALWAYS,
        (true, false, false) => OPEN_ALWAYS,
        (false, _, true) => TRUNCATE_EXISTING,
        (false, _, false) => OPEN_EXISTING,
    };
    let attributes = if oflag & O_CREAT != 0 && pmode & S_IWRITE == 0 {
        FILE_ATTRIBUTE_READONLY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    let text = if oflag & O_BINARY != 0 {
        false
    } else if oflag & O_TEXT != 0 {
        true
    } else {
        fmode != O_BINARY
    };
    let inherit = oflag & O_NOINHERIT == 0;
    let mut mode = FOPEN;
    if text {
        mode |= FTEXT;
    }
    if oflag & O_APPEND != 0 {
        mode |= FAPPEND;
    }
    if !inherit {
        mode |= FNOINHERIT;
    }
    Some(OpenPlan {
        access,
        disposition,
        attributes,
        inherit,
        mode,
    })
}

/// _open: the file `name` opened (or created) as `oflag` says (see [`open_plan`]), shared for
/// reading and writing (`_SH_DENYNO`), on the lowest free descriptor. -1 with EINVAL for an access
/// mode that is none, EMFILE when no descriptor is free, and errno and `_doserrno` from
/// CreateFileA's error when the file cannot be opened.
///
/// cdecl: the caller pushes the arguments and takes them back, so the optional `pmode` is this
/// function's third parameter, read only with `_O_CREAT` (MSDN's prototype: `_open(filename,
/// oflag [, pmode])`).
///
/// # Safety
///
/// `name` is a NUL-terminated string; `pmode` is passed when `oflag` holds `_O_CREAT`.
#[unsafe(export_name = "f2k_export__open")]
pub unsafe extern "C" fn open_file(name: *const u8, oflag: i32, pmode: i32) -> i32 {
    let pmode = if oflag & O_CREAT != 0 { pmode } else { 0 };
    let Some(plan) = open_plan(oflag, pmode, crate::data::FMODE.read()) else {
        set_errno(EINVAL);
        thread::set_doserrno(0);
        return -1;
    };
    let _lock = Locked::take();
    let Some(fd) = free_descriptor() else {
        return -1;
    };
    let security = imports::SecurityAttributes::inheritable(plan.inherit);
    // SAFETY: kernel32's export, over the caller's name and the attributes above.
    let handle = unsafe {
        imports::CreateFileA(
            name,
            plan.access,
            FILE_SHARE_READ_WRITE,
            &security,
            plan.disposition,
            plan.attributes,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: kernel32's export.
        set_dos_error(unsafe { imports::GetLastError() });
        return -1;
    }
    // SAFETY: kernel32's export, over the handle just opened.
    let kind = unsafe { imports::GetFileType(handle) };
    if kind == FILE_TYPE_UNKNOWN {
        // SAFETY: kernel32's export, over the handle just opened.
        unsafe { imports::CloseHandle(handle) };
        set_errno(EBADF);
        thread::set_doserrno(0);
        return -1;
    }
    table()[fd] = Descriptor {
        handle: usize::MAX,
        flags: plan.mode | type_flags(kind),
        ahead: 0x100,
    };
    set_handle(fd, handle);
    fd as i32
}

/// _get_osfhandle: the descriptor's handle; -1 with EBADF when it is not open.
#[unsafe(export_name = "f2k_export__get_osfhandle")]
pub extern "C" fn get_osfhandle(fd: i32) -> isize {
    match open(fd) {
        Some(entry) => entry.handle as isize,
        None => -1,
    }
}

/// _close: the descriptor and its handle closed; -1 with EBADF when it is not open.
#[unsafe(export_name = "f2k_export__close")]
pub extern "C" fn close(fd: i32) -> i32 {
    let _lock = Locked::take();
    let Some(entry) = open(fd) else {
        return -1;
    };
    let handle = entry.handle;
    // Descriptors 1 and 2 on one handle: the other keeps it.
    let shared = (fd == 1 || fd == 2)
        && table()[3 - fd as usize].flags & FOPEN != 0
        && table()[3 - fd as usize].handle == handle;
    let mut result = 0;
    // SAFETY: kernel32's export, over the descriptor's own handle.
    if !shared && unsafe { imports::CloseHandle(handle) } == 0 {
        // SAFETY: kernel32's export.
        set_dos_error(unsafe { imports::GetLastError() });
        result = -1;
    }
    free(fd as usize);
    result
}

/// A handle duplicated within the process, inheritable, its access the same; none (errno from the
/// error) when it cannot be.
fn duplicate(handle: usize) -> Option<usize> {
    let mut copy = 0usize;
    // SAFETY: kernel32's exports.
    unsafe {
        let process = imports::GetCurrentProcess();
        if imports::DuplicateHandle(process, handle, process, &mut copy, 0, 1, 2) == 0 {
            set_dos_error(imports::GetLastError());
            return None;
        }
    }
    Some(copy)
}

/// _dup: a second descriptor for the same file, the lowest free one.
#[unsafe(export_name = "f2k_export__dup")]
pub extern "C" fn dup(fd: i32) -> i32 {
    let _lock = Locked::take();
    let Some(entry) = open(fd) else {
        return -1;
    };
    let (handle, flags) = (entry.handle, entry.flags);
    let Some(new) = free_descriptor() else {
        return -1;
    };
    let Some(copy) = duplicate(handle) else {
        return -1;
    };
    table()[new] = Descriptor {
        handle: usize::MAX,
        flags: flags & !(FNOINHERIT | FEOF),
        ahead: 0x100,
    };
    set_handle(new, copy);
    new as i32
}

/// _dup2: descriptor `to` made a second descriptor for `from`'s file, closing what it held.
#[unsafe(export_name = "f2k_export__dup2")]
pub extern "C" fn dup2(from: i32, to: i32) -> i32 {
    let _lock = Locked::take();
    let Some(entry) = open(from) else {
        return -1;
    };
    let (handle, flags) = (entry.handle, entry.flags);
    if !(0..DESCRIPTORS as i32).contains(&to) {
        set_errno(EBADF);
        thread::set_doserrno(0);
        return -1;
    }
    if from == to {
        return 0;
    }
    let Some(copy) = duplicate(handle) else {
        return -1;
    };
    if table()[to as usize].flags & FOPEN != 0 {
        close(to);
    }
    table()[to as usize] = Descriptor {
        handle: usize::MAX,
        flags: flags & !(FNOINHERIT | FEOF),
        ahead: 0x100,
    };
    set_handle(to as usize, copy);
    0
}

/// _setmode: the descriptor's translation mode set; the previous one.
#[unsafe(export_name = "f2k_export__setmode")]
pub extern "C" fn setmode(fd: i32, mode: i32) -> i32 {
    let _lock = Locked::take();
    let Some(entry) = open(fd) else {
        return -1;
    };
    let previous = if entry.flags & FTEXT != 0 {
        O_TEXT
    } else {
        O_BINARY
    };
    match mode {
        O_TEXT => entry.flags |= FTEXT,
        O_BINARY => entry.flags &= !FTEXT,
        _ => {
            set_errno(EINVAL);
            return -1;
        }
    }
    previous
}

/// The descriptor's file pointer moved (SetFilePointer's methods), its end-of-file mark cleared;
/// the new position, or -1.
pub fn seek(fd: i32, offset: i32, origin: u32) -> i32 {
    let Some(entry) = open(fd) else {
        return -1;
    };
    // SAFETY: kernel32's exports, over the descriptor's handle.
    unsafe {
        imports::SetLastError(0);
        let position = imports::SetFilePointer(entry.handle, offset, core::ptr::null_mut(), origin);
        let error = imports::GetLastError();
        if position == u32::MAX && error != 0 {
            set_dos_error(error);
            return -1;
        }
        entry.flags &= !FEOF;
        position as i32
    }
}

/// _tell: the descriptor's file position.
#[unsafe(export_name = "f2k_export__tell")]
pub extern "C" fn tell(fd: i32) -> i32 {
    seek(fd, 0, 1)
}

/// WriteFile over the whole of `bytes`: the count written, or the error.
fn write_all(handle: usize, bytes: &[u8]) -> Result<usize, u32> {
    let mut written = 0u32;
    // SAFETY: kernel32's exports, over the slice.
    unsafe {
        if imports::WriteFile(handle, bytes.as_ptr(), bytes.len() as u32, &mut written, 0) == 0 {
            return Err(imports::GetLastError());
        }
    }
    Ok(written as usize)
}

/// _write: `count` bytes to the descriptor, each LF as CR LF in text mode, at the file's end when
/// it appends; the caller's bytes written, or -1 (EBADF for a descriptor not open or not writable,
/// ENOSPC when nothing could be written).
///
/// # Safety
///
/// `buffer` holds `count` bytes.
#[unsafe(export_name = "f2k_export__write")]
pub unsafe extern "C" fn write(fd: i32, buffer: *const u8, count: u32) -> i32 {
    let Some(entry) = open(fd) else {
        return -1;
    };
    if count == 0 {
        return 0;
    }
    let (handle, flags) = (entry.handle, entry.flags);
    if flags & FAPPEND != 0 {
        seek(fd, 0, 2);
    }
    // SAFETY: the caller's buffer.
    let bytes = unsafe { core::slice::from_raw_parts(buffer, count as usize) };
    let (mut consumed, mut stored, mut failure) = (0usize, 0usize, None);
    if flags & FTEXT == 0 {
        match write_all(handle, bytes) {
            Ok(written) => {
                consumed = written;
                stored = written;
            }
            Err(error) => failure = Some(error),
        }
    } else {
        // The translation, a chunk at a time.
        let mut chunk = [0u8; 1024];
        let mut at = 0;
        while at < bytes.len() {
            let (mut length, start) = (0, at);
            while at < bytes.len() && length < chunk.len() - 1 {
                if bytes[at] == b'\n' {
                    chunk[length] = b'\r';
                    length += 1;
                }
                chunk[length] = bytes[at];
                length += 1;
                at += 1;
            }
            match write_all(handle, &chunk[..length]) {
                Ok(written) => {
                    stored += written;
                    if written < length {
                        // A full disk: the caller's bytes whose translation went out whole.
                        let mut out = 0;
                        for &byte in &bytes[start..at] {
                            out += if byte == b'\n' { 2 } else { 1 };
                            if out > written {
                                break;
                            }
                            consumed += 1;
                        }
                        break;
                    }
                    consumed += at - start;
                }
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
    }
    if stored == 0 {
        if let Some(error) = failure {
            if error == ERROR_ACCESS_DENIED {
                set_errno(EBADF);
                thread::set_doserrno(error);
            } else {
                set_dos_error(error);
            }
            return -1;
        }
        if flags & FDEV != 0 && bytes[0] == CTRL_Z {
            return 0;
        }
        set_errno(ENOSPC);
        thread::set_doserrno(0);
        return -1;
    }
    consumed as i32
}

/// The descriptor's next bytes into `buffer`, CR LF read as LF and Ctrl-Z the end of a file in
/// text mode: the count, 0 at the end, -1 (errno) on an error.
///
/// # Safety
///
/// `buffer` holds `count` bytes.
pub unsafe fn read(fd: i32, buffer: *mut u8, count: usize) -> i32 {
    let Some(entry) = open(fd) else {
        return -1;
    };
    if count == 0 || entry.flags & FEOF != 0 {
        return 0;
    }
    // SAFETY: the caller's buffer.
    let bytes = unsafe { core::slice::from_raw_parts_mut(buffer, count) };
    let mut got = 0;
    if entry.ahead != 0x100 && entry.flags & (FPIPE | FDEV) != 0 {
        bytes[0] = entry.ahead as u8;
        entry.ahead = 0x100;
        got = 1;
    }
    let mut read = 0u32;
    // SAFETY: kernel32's exports, over the rest of the buffer.
    unsafe {
        if got < count
            && imports::ReadFile(
                entry.handle,
                bytes[got..].as_mut_ptr(),
                (count - got) as u32,
                &mut read,
                0,
            ) == 0
        {
            let error = imports::GetLastError();
            match error {
                ERROR_BROKEN_PIPE => return got as i32,
                ERROR_ACCESS_DENIED => {
                    set_errno(EBADF);
                    thread::set_doserrno(error);
                    return -1;
                }
                _ => {
                    set_dos_error(error);
                    return -1;
                }
            }
        }
    }
    got += read as usize;
    if entry.flags & FTEXT == 0 {
        return got as i32;
    }
    // The translation, in place.
    let (mut from, mut to) = (0, 0);
    while from < got {
        let byte = bytes[from];
        if byte == CTRL_Z && entry.flags & FDEV == 0 {
            entry.flags |= FEOF;
            break;
        }
        if byte != b'\r' {
            bytes[to] = byte;
            to += 1;
            from += 1;
            continue;
        }
        if from + 1 < got {
            if bytes[from + 1] == b'\n' {
                bytes[to] = b'\n';
                from += 2;
            } else {
                bytes[to] = b'\r';
                from += 1;
            }
            to += 1;
            continue;
        }
        // A CR last: the next byte decides.
        from += 1;
        let (mut next, mut one) = (0u8, 0u32);
        // SAFETY: kernel32's export, over one byte.
        let peeked =
            unsafe { imports::ReadFile(entry.handle, &mut next, 1, &mut one, 0) } != 0 && one == 1;
        if peeked && next == b'\n' {
            bytes[to] = b'\n';
        } else {
            bytes[to] = b'\r';
            if peeked {
                if entry.flags & (FPIPE | FDEV) != 0 {
                    entry.ahead = next as u16;
                } else {
                    // SAFETY: kernel32's export: the byte given back to the file.
                    unsafe { imports::SetFilePointer(entry.handle, -1, core::ptr::null_mut(), 1) };
                }
            }
        }
        to += 1;
    }
    to as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(oflag: i32, pmode: i32, fmode: i32) -> OpenPlan {
        open_plan(oflag, pmode, fmode).expect("an access mode")
    }

    /// The access mode is the low two bits: read, write, both; the fourth value is none.
    #[test]
    fn the_access_mode_is_the_low_bits() {
        assert_eq!(plan(O_RDONLY, 0, 0).access, GENERIC_READ);
        assert_eq!(plan(O_WRONLY, 0, 0).access, GENERIC_WRITE);
        assert_eq!(plan(O_RDWR, 0, 0).access, GENERIC_READ | GENERIC_WRITE);
        assert_eq!(open_plan(O_ACCESS, 0, 0), None);
    }

    /// `_O_CREAT`, `_O_EXCL` and `_O_TRUNC` choose the disposition; `_O_EXCL` alone means
    /// nothing; a file created without `_S_IWRITE` is read-only.
    #[test]
    fn the_creation_flags_choose_the_disposition() {
        let disposition = |oflag| plan(O_WRONLY | oflag, S_IWRITE, 0).disposition;
        assert_eq!(disposition(0), OPEN_EXISTING);
        assert_eq!(disposition(O_EXCL), OPEN_EXISTING);
        assert_eq!(disposition(O_TRUNC), TRUNCATE_EXISTING);
        assert_eq!(disposition(O_CREAT), OPEN_ALWAYS);
        assert_eq!(disposition(O_CREAT | O_TRUNC), CREATE_ALWAYS);
        assert_eq!(disposition(O_CREAT | O_EXCL), CREATE_NEW);
        assert_eq!(disposition(O_CREAT | O_EXCL | O_TRUNC), CREATE_NEW);
        let attributes = |oflag, pmode| plan(O_WRONLY | oflag, pmode, 0).attributes;
        assert_eq!(attributes(O_CREAT, S_IWRITE), FILE_ATTRIBUTE_NORMAL);
        assert_eq!(attributes(O_CREAT, 0x0100), FILE_ATTRIBUTE_READONLY);
        assert_eq!(attributes(0, 0), FILE_ATTRIBUTE_NORMAL);
    }

    /// The descriptor's flags as spawn's crtfds capture shows them handed to a child: a file read
    /// in binary 0x01, one written appending in text 0xA1, one opened `_O_NOINHERIT` not
    /// inheritable; `_fmode` decides the translation when the flags do not.
    #[test]
    fn the_mode_flags_match_the_capture() {
        let binary = plan(O_RDONLY | O_BINARY, 0, 0);
        assert_eq!((binary.mode, binary.inherit), (0x01, true));
        let appending = plan(O_WRONLY | O_CREAT | O_APPEND | O_TEXT, 0x0180, 0);
        assert_eq!(appending.mode, 0xA1);
        let private = plan(O_RDONLY | O_NOINHERIT, 0, 0);
        assert_eq!(
            (private.mode & FNOINHERIT, private.inherit),
            (FNOINHERIT, false)
        );
        assert_eq!(private.mode & FTEXT, FTEXT, "_fmode 0 is text");
        assert_eq!(plan(O_RDONLY, 0, O_BINARY).mode & FTEXT, 0);
        assert_eq!(plan(O_RDONLY, 0, O_TEXT).mode & FTEXT, FTEXT);
        assert_eq!(plan(O_RDONLY | O_TEXT, 0, O_BINARY).mode & FTEXT, FTEXT);
        assert_eq!(plan(O_RDONLY | O_BINARY | O_TEXT, 0, 0).mode & FTEXT, 0);
    }
}
