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

use core::sync::atomic::{AtomicI32, Ordering::Relaxed};

use rtl::sync::Locked;

use crate::imports;
use crate::thread::{self, set_dos_error, set_errno, Held, Lock, EBADF, EINVAL, EMFILE, ENOSPC};

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
    /// The ticket of the [`Reservation`] holding the descriptor (none: 0).
    ticket: u32,
}

const CLOSED: Descriptor = Descriptor {
    handle: usize::MAX,
    flags: 0,
    ahead: 0x100,
    ticket: 0,
};

impl Descriptor {
    /// A descriptor open over `handle` with the mode `flags` (FOPEN added), nothing read ahead.
    const fn open(handle: usize, flags: u8) -> Descriptor {
        Descriptor {
            handle,
            flags: flags | FOPEN,
            ..CLOSED
        }
    }

    fn is_open(&self) -> bool {
        self.flags & FOPEN != 0
    }

    /// Neither open nor reserved: an open may take it.
    fn is_free(&self) -> bool {
        !self.is_open() && self.ticket == 0
    }
}

/// The descriptor table: the descriptors, and the last reservation's ticket.
struct Table {
    entries: [Descriptor; DESCRIPTORS],
    tickets: u32,
}

impl Table {
    /// The lowest free descriptor.
    fn lowest_free(&self) -> Option<usize> {
        self.entries.iter().position(Descriptor::is_free)
    }

    /// Descriptor `fd` reserved (closed, held by a new ticket): the ticket.
    fn reserve(&mut self, fd: usize) -> u32 {
        self.tickets = self.tickets.wrapping_add(1).max(1);
        self.entries[fd] = Descriptor {
            ticket: self.tickets,
            ..CLOSED
        };
        self.tickets
    }

    /// `descriptor` stored on the lowest free descriptor: which one, or none when every one is
    /// open or reserved.
    fn place(&mut self, descriptor: Descriptor) -> Option<usize> {
        let fd = self.lowest_free()?;
        self.entries[fd] = descriptor;
        Some(fd)
    }
}

/// The descriptor table, behind its lock (Windows 2000's msvcrt has one for its descriptor
/// table). The lock is held only to copy or change entries, never across a kernel32 call that can
/// wait: across those, each descriptor has its own lock ([`IO`]), and a descriptor being opened or
/// closed is held by a [`Reservation`].
static TABLE: Locked<Table, Lock> = Locked::new(
    Lock::new(),
    Table {
        entries: [CLOSED; DESCRIPTORS],
        tickets: 0,
    },
);

/// Each descriptor's own lock (Windows 2000's `_lock_fh`): held across its reads, writes and
/// seeks, its close, and the duplicating of its handle, so that one descriptor's operations come
/// one at a time; a thread waiting on one (stdin, reading the console) keeps no other descriptor
/// from the rest. Two are taken in ascending order (`_dup2`); the table's lock is taken inside.
static IO: [Lock; DESCRIPTORS] = [const { Lock::new() }; DESCRIPTORS];

/// __set_app_type's value: 1 for a console program (whose descriptors 0 to 2 keep the standard
/// handles in step), 2 for a GUI one, 0 before the program says.
static APP_TYPE: AtomicI32 = AtomicI32::new(0);

/// __set_app_type's work: the program's kind.
pub fn set_app_type(kind: i32) {
    APP_TYPE.store(kind, Relaxed);
}

/// `f` run over the descriptor table under its lock. `f` must not reach the table again (through
/// this function or a helper built on it): the lock refuses that with a panic.
fn with_table<R>(f: impl FnOnce(&mut Table) -> R) -> R {
    TABLE.with(f)
}

/// Descriptor `fd`'s own lock taken, for the guard's life; none for a descriptor out of range.
fn hold(fd: i32) -> Option<Held<'static>> {
    let fd = usize::try_from(fd).ok()?;
    IO.get(fd).map(Lock::hold)
}

/// Descriptor `fd`'s entry, a copy, open or not; none when `fd` is out of range.
fn descriptor(fd: i32) -> Option<Descriptor> {
    let fd = usize::try_from(fd).ok()?;
    with_table(|table| table.entries.get(fd).copied())
}

/// The errno and `_doserrno` of a descriptor that is not open: EBADF.
fn not_open() {
    set_errno(EBADF);
    thread::set_doserrno(0);
}

/// The errno and `_doserrno` when no descriptor is free: EMFILE.
fn none_free() {
    set_errno(EMFILE);
    thread::set_doserrno(0);
}

/// The open descriptor `fd`'s entry, a copy, or none (errno EBADF).
fn open(fd: i32) -> Option<Descriptor> {
    let entry = descriptor(fd).filter(Descriptor::is_open);
    if entry.is_none() {
        not_open();
    }
    entry
}

/// Descriptor `fd` (in range) set to `descriptor`.
fn store(fd: usize, descriptor: Descriptor) {
    with_table(|table| table.entries[fd] = descriptor);
}

/// Descriptor `fd`'s entry changed by `change`, if it is still open over `handle`. A caller that
/// copied the entry and let the table's lock go (for a kernel32 call that can block, so that one
/// thread waiting on the console does not stop another's output) writes back what changed only
/// when no other thread closed or reused the descriptor meanwhile. What `change` answers, or none.
fn update<R>(fd: i32, handle: usize, change: impl FnOnce(&mut Descriptor) -> R) -> Option<R> {
    let fd = usize::try_from(fd).ok()?;
    with_table(|table| {
        table
            .entries
            .get_mut(fd)
            .filter(|entry| entry.is_open() && entry.handle == handle)
            .map(change)
    })
}

/// A descriptor held while an open or a close is under way: kernel32 opens or closes its handle
/// without the table's lock, and meanwhile the descriptor reads as closed and no other open takes
/// it. Dropped, the descriptor is free again (unless `_dup2` took it meanwhile).
struct Reservation {
    fd: usize,
    ticket: u32,
}

impl Reservation {
    /// The lowest free descriptor, reserved; none (errno EMFILE) when every one is open or
    /// reserved.
    fn lowest() -> Option<Reservation> {
        let reserved = with_table(|table| {
            let fd = table.lowest_free()?;
            let ticket = table.reserve(fd);
            Some(Reservation { fd, ticket })
        });
        if reserved.is_none() {
            none_free();
        }
        reserved
    }

    /// The open descriptor `fd` reserved for its close, and the handle the close is to close: none
    /// when descriptor 1 and 2 share it and the other stays open (it keeps the handle). None
    /// (errno EBADF) when `fd` is not open.
    fn closing(fd: i32) -> Option<(Reservation, Option<usize>)> {
        let reserved = usize::try_from(fd).ok().and_then(|fd| {
            with_table(|table| {
                let entry = *table.entries.get(fd).filter(|entry| entry.is_open())?;
                let shared = (fd == 1 || fd == 2) && {
                    let other = table.entries[3 - fd];
                    other.is_open() && other.handle == entry.handle
                };
                let ticket = table.reserve(fd);
                Some((
                    Reservation { fd, ticket },
                    (!shared).then_some(entry.handle),
                ))
            })
        });
        if reserved.is_none() {
            not_open();
        }
        reserved
    }

    /// The reserved descriptor made `descriptor`: which one it is. `_dup2` may have taken it
    /// meanwhile (a reserved descriptor is not open): then the lowest free one serves instead, or
    /// none when there is none (the caller's errno EMFILE).
    fn fill(self, descriptor: Descriptor) -> Option<usize> {
        let (fd, ticket) = (self.fd, self.ticket);
        core::mem::forget(self);
        let placed = with_table(|table| {
            if table.entries[fd].ticket == ticket {
                table.entries[fd] = descriptor;
                Some(fd)
            } else {
                table.place(descriptor)
            }
        });
        if let Some(fd) = placed {
            follow_standard(fd, descriptor.handle);
        }
        placed
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        with_table(|table| {
            let entry = &mut table.entries[self.fd];
            if entry.ticket == self.ticket {
                *entry = CLOSED;
            }
        });
    }
}

/// The descriptors up to the last one open: those a child inherits.
fn inherited_count(table: &[Descriptor]) -> usize {
    table
        .iter()
        .rposition(Descriptor::is_open)
        .map_or(0, |last| last + 1)
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
pub struct Inheritance<'a>(&'a [Descriptor]);

impl Inheritance<'_> {
    /// The block's length.
    pub fn length(&self) -> usize {
        inheritance_length(self.0.len())
    }

    /// The block into `out`, of [`Inheritance::length`].
    pub fn write(&self, out: &mut [u8]) {
        let descriptors = self.0.iter().map(|entry| {
            if entry.is_open() && entry.flags & FNOINHERIT == 0 {
                (entry.flags, entry.handle as u32)
            } else {
                (0, u32::MAX)
            }
        });
        encode_inheritance(descriptors, out);
    }
}

/// `body` run over the descriptors a child inherits, with the descriptor table held still: no
/// descriptor opens or starts closing until `body` returns, so a child created inside it gets
/// handles that are still open. `body` must not reach the descriptors itself (the table's lock
/// refuses that with a panic).
pub fn with_inheritance<R>(body: impl FnOnce(Inheritance<'_>) -> R) -> R {
    with_table(|table| {
        let count = inherited_count(&table.entries);
        body(Inheritance(&table.entries[..count]))
    })
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
        store(fd, Descriptor::open(handle, flags));
    }
}

/// The DLL's process attach: the descriptors the parent handed on, then those of 0 to 2 it did
/// not over the standard handles, in text mode.
pub fn initialize() {
    take_inherited();
    for (fd, &which) in STANDARD.iter().enumerate() {
        if descriptor(fd as i32).is_some_and(|entry| entry.is_open()) {
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
        let kind = if kind == FILE_TYPE_UNKNOWN {
            FDEV
        } else {
            type_flags(kind)
        };
        store(fd, Descriptor::open(handle, FTEXT | kind));
    }
}

/// Whether `fd` is a character device (the console).
pub fn is_device(fd: i32) -> bool {
    descriptor(fd).is_some_and(|entry| entry.flags & (FOPEN | FDEV) == FOPEN | FDEV)
}

/// A standard descriptor's new handle (0 once it is closed) made the standard handle too, in a
/// console program.
fn follow_standard(fd: usize, handle: usize) {
    if fd < 3 && APP_TYPE.load(Relaxed) == 1 {
        // SAFETY: kernel32's export.
        unsafe { imports::SetStdHandle(STANDARD[fd], handle) };
    }
}

/// CloseHandle over a handle the C runtime opened or duplicated: the error, when it fails.
fn close_handle(handle: usize) -> Result<(), u32> {
    // SAFETY: kernel32's exports.
    unsafe {
        if imports::CloseHandle(handle) == 0 {
            return Err(imports::GetLastError());
        }
    }
    Ok(())
}

/// `descriptor` made a new descriptor over a handle the C runtime opened (or duplicated) on the
/// `reservation`: the descriptor's number, or -1 with EMFILE, the handle closed, when none is
/// left.
fn install(reservation: Reservation, descriptor: Descriptor) -> i32 {
    match reservation.fill(descriptor) {
        Some(fd) => fd as i32,
        None => {
            let _ = close_handle(descriptor.handle);
            none_free();
            -1
        }
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
    let mut mode = type_flags(kind);
    if flags & O_TEXT != 0 {
        mode |= FTEXT;
    }
    if flags & O_APPEND != 0 {
        mode |= FAPPEND;
    }
    if flags & O_NOINHERIT != 0 {
        mode |= FNOINHERIT;
    }
    // The handle is the caller's: on no free descriptor, it stays open.
    match with_table(|table| table.place(Descriptor::open(handle, mode))) {
        Some(fd) => {
            follow_standard(fd, handle);
            fd as i32
        }
        None => {
            none_free();
            -1
        }
    }
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
    // The descriptor is held for the open, without the table's lock: CreateFileA can wait (on a
    // device, a pipe, a file system).
    let Some(reservation) = Reservation::lowest() else {
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
        let _ = close_handle(handle);
        not_open();
        return -1;
    }
    install(
        reservation,
        Descriptor::open(handle, plan.mode | type_flags(kind)),
    )
}

/// _get_osfhandle: the descriptor's handle; -1 with EBADF when it is not open.
#[unsafe(export_name = "f2k_export__get_osfhandle")]
pub extern "C" fn get_osfhandle(fd: i32) -> isize {
    match open(fd) {
        Some(entry) => entry.handle as isize,
        None => -1,
    }
}

/// _close: the descriptor and its handle closed; -1 with EBADF when it is not open. Descriptors 1
/// and 2 on one handle, the other keeps it open. The descriptor's lock is held throughout, the
/// table's only to look at it and to free it: the descriptor stays reserved across CloseHandle.
#[unsafe(export_name = "f2k_export__close")]
pub extern "C" fn close(fd: i32) -> i32 {
    let _io = hold(fd);
    let Some((reservation, handle)) = Reservation::closing(fd) else {
        return -1;
    };
    let mut result = 0;
    if let Some(Err(error)) = handle.map(close_handle) {
        set_dos_error(error);
        result = -1;
    }
    drop(reservation);
    follow_standard(fd as usize, 0);
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

/// _dup: a second descriptor for the same file, the lowest free one. The descriptor's lock is held,
/// so it is not closed while its handle is duplicated.
#[unsafe(export_name = "f2k_export__dup")]
pub extern "C" fn dup(fd: i32) -> i32 {
    let _io = hold(fd);
    let Some(entry) = open(fd) else {
        return -1;
    };
    let Some(reservation) = Reservation::lowest() else {
        return -1;
    };
    let Some(copy) = duplicate(entry.handle) else {
        return -1;
    };
    install(
        reservation,
        Descriptor::open(copy, entry.flags & !(FNOINHERIT | FEOF)),
    )
}

/// _dup2: descriptor `to` made a second descriptor for `from`'s file, closing what it held. Both
/// descriptors' locks are held (in ascending order), and `to` changes in one step under the table's
/// lock, so no open takes it between its close and its reuse. One that an open has reserved is
/// taken over: the open finds another.
#[unsafe(export_name = "f2k_export__dup2")]
pub extern "C" fn dup2(from: i32, to: i32) -> i32 {
    let _first = hold(from.min(to));
    let _second = if from == to { None } else { hold(from.max(to)) };
    let Some(entry) = open(from) else {
        return -1;
    };
    if !(0..DESCRIPTORS as i32).contains(&to) {
        not_open();
        return -1;
    }
    if from == to {
        return 0;
    }
    let Some(copy) = duplicate(entry.handle) else {
        return -1;
    };
    let to = to as usize;
    let replaced = with_table(|table| {
        let old = table.entries[to];
        // Descriptors 1 and 2 on one handle: the other keeps it.
        let shared = (to == 1 || to == 2) && {
            let other = table.entries[3 - to];
            other.is_open() && other.handle == old.handle
        };
        table.entries[to] = Descriptor::open(copy, entry.flags & !(FNOINHERIT | FEOF));
        (old.is_open() && !shared).then_some(old.handle)
    });
    if let Some(Err(error)) = replaced.map(close_handle) {
        set_dos_error(error);
    }
    follow_standard(to, copy);
    0
}

/// _setmode: the descriptor's translation mode set; the previous one.
#[unsafe(export_name = "f2k_export__setmode")]
pub extern "C" fn setmode(fd: i32, mode: i32) -> i32 {
    let _io = hold(fd);
    let Some(entry) = open(fd) else {
        return -1;
    };
    let previous = if entry.flags & FTEXT != 0 {
        O_TEXT
    } else {
        O_BINARY
    };
    let text = match mode {
        O_TEXT => true,
        O_BINARY => false,
        _ => {
            set_errno(EINVAL);
            return -1;
        }
    };
    update(fd, entry.handle, |entry| {
        if text {
            entry.flags |= FTEXT;
        } else {
            entry.flags &= !FTEXT;
        }
    });
    previous
}

/// The descriptor's file pointer moved (SetFilePointer's methods), its end-of-file mark cleared;
/// the new position, or -1. The descriptor's lock is held across SetFilePointer, the table's is
/// not.
pub fn seek(fd: i32, offset: i32, origin: u32) -> i32 {
    let _io = hold(fd);
    let Some(entry) = open(fd) else {
        return -1;
    };
    // SAFETY: kernel32's exports, over the descriptor's handle.
    let (position, error) = unsafe {
        imports::SetLastError(0);
        let position = imports::SetFilePointer(entry.handle, offset, core::ptr::null_mut(), origin);
        (position, imports::GetLastError())
    };
    if position == u32::MAX && error != 0 {
        set_dos_error(error);
        return -1;
    }
    update(fd, entry.handle, |entry| entry.flags &= !FEOF);
    position as i32
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
/// ENOSPC when nothing could be written). The descriptor's lock is held across WriteFile (so two
/// threads' writes to one descriptor do not interleave); the table's is taken only to read the
/// descriptor.
///
/// # Safety
///
/// `buffer` holds `count` bytes.
#[unsafe(export_name = "f2k_export__write")]
pub unsafe extern "C" fn write(fd: i32, buffer: *const u8, count: u32) -> i32 {
    let _io = hold(fd);
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
/// text mode: the count, 0 at the end, -1 (errno) on an error. The descriptor's lock is held across
/// ReadFile; the table's is taken only to read the descriptor and write back its byte read ahead
/// and its end-of-file mark: a thread waiting on the console does not stop another's output.
///
/// # Safety
///
/// `buffer` holds `count` bytes.
pub unsafe fn read(fd: i32, buffer: *mut u8, count: usize) -> i32 {
    let _io = hold(fd);
    let Some(entry) = open(fd) else {
        return -1;
    };
    let (handle, flags) = (entry.handle, entry.flags);
    if count == 0 || flags & FEOF != 0 {
        return 0;
    }
    // SAFETY: the caller's buffer.
    let bytes = unsafe { core::slice::from_raw_parts_mut(buffer, count) };
    let mut got = 0;
    if entry.ahead != 0x100 && flags & (FPIPE | FDEV) != 0 {
        // Taken under the table's lock, and the entry checked still open over the same handle.
        let ahead = update(fd, handle, |entry| {
            core::mem::replace(&mut entry.ahead, 0x100)
        });
        if let Some(ahead) = ahead.filter(|&ahead| ahead != 0x100) {
            bytes[0] = ahead as u8;
            got = 1;
        }
    }
    let mut read = 0u32;
    // SAFETY: kernel32's exports, over the rest of the buffer.
    unsafe {
        if got < count
            && imports::ReadFile(
                handle,
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
    if flags & FTEXT == 0 {
        return got as i32;
    }
    // The translation, in place.
    let (mut from, mut to) = (0, 0);
    while from < got {
        let byte = bytes[from];
        if byte == CTRL_Z && flags & FDEV == 0 {
            update(fd, handle, |entry| entry.flags |= FEOF);
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
            unsafe { imports::ReadFile(handle, &mut next, 1, &mut one, 0) } != 0 && one == 1;
        if peeked && next == b'\n' {
            bytes[to] = b'\n';
        } else {
            bytes[to] = b'\r';
            if peeked {
                if flags & (FPIPE | FDEV) != 0 {
                    update(fd, handle, |entry| entry.ahead = u16::from(next));
                } else {
                    // SAFETY: kernel32's export: the byte given back to the file.
                    unsafe { imports::SetFilePointer(handle, -1, core::ptr::null_mut(), 1) };
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

    /// A reserved descriptor reads as closed but is not free: the next open takes the one after
    /// it; dropped, it is free again. One that `_dup2` took meanwhile is filled elsewhere, and its
    /// reservation's drop leaves it alone. (The only host test that reaches the table.)
    #[test]
    fn a_reservation_holds_its_descriptor() {
        let first = Reservation::lowest().expect("a free descriptor");
        assert!(descriptor(first.fd as i32).is_some_and(|entry| !entry.is_open()));
        let second = Reservation::lowest().expect("a free descriptor");
        assert_eq!(second.fd, first.fd + 1);
        let (first_fd, second_fd) = (first.fd, second.fd);
        drop(first);
        let again = Reservation::lowest().expect("a free descriptor");
        assert_eq!(again.fd, first_fd);

        // `_dup2` takes the reserved descriptor: the open lands on the lowest free one instead.
        store(again.fd, Descriptor::open(0x44, FTEXT));
        let placed = again.fill(Descriptor::open(0x48, 0));
        assert_eq!(placed, Some(second_fd + 1));
        drop(second);
        assert_eq!(
            descriptor(first_fd as i32).map(|entry| entry.handle),
            Some(0x44)
        );
        assert!(descriptor(second_fd as i32).is_some_and(|entry| entry.is_free()));
        for fd in [first_fd, second_fd + 1] {
            store(fd, CLOSED);
        }
    }

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
