//! stdio: streams over the descriptors (`_iob`'s `FILE`s), and the formatted-output exports.
//!
//! As fd's and crt's captures pin them:
//!
//! - A stream gets a 4096-byte buffer of its own on its first transfer (`_IOMYBUF`); `_cnt` is the
//!   room left in it while writing (0 once flushed: the next character starts it again), the bytes
//!   left to read while reading. Text mode is the descriptor's, applied when the buffer goes out or
//!   comes in.
//! - stdout and stderr writing to a character device have no buffer of their own: each call's
//!   output goes out at its end, through a buffer lent for the call (MSDN: "flushed … after each
//!   library call" on a device). Writing to a file, they are buffered like any stream.
//! - setvbuf flushes, then gives the stream the caller's buffer (`_IOYOURBUF | _IOSETVBUF`), one of
//!   its own of that size, or none (`_IONBF`).
//! - fflush(NULL) flushes every stream writing; fflush of a stream reading drops what it holds.
//! - fgets reads to a newline (kept), to `n - 1` bytes, or to the end; NULL when the end comes
//!   first; the end sets `_IOEOF` (feof).
//! - fclose flushes, frees the stream's own buffer and closes its descriptor.
//!
//! Each stream has its own lock, as on Windows 2000 ([`with_stream`]): a call holds its stream's
//! across the descriptor's reads and writes, so a thread waiting on stdin (reading the console)
//! keeps no other stream from the rest.

use rtl::sync::Locked;

use crate::data::{File, IOB, IOB_ENTRIES, STREAM_BUFFER};
use crate::format::{self, Args, Output, VaList};
use crate::lowio;
use crate::thread::{set_errno, Lock, EBADF, EINVAL, EMFILE};

/// The `_flag` bits (stdio.h's, and the C runtime's own: `_IOYOURBUF` a buffer the stream does not
/// own, `_IOSETVBUF` one setvbuf gave, `TEMPORARY` one lent for a call).
const IOREAD: i32 = 0x0001;
const IOWRT: i32 = 0x0002;
const IONBF: i32 = 0x0004;
const IOMYBUF: i32 = 0x0008;
const IOEOF: i32 = 0x0010;
const IOERR: i32 = 0x0020;
const IOSTRG: i32 = 0x0040;
const IORW: i32 = 0x0080;
const IOYOURBUF: i32 = 0x0100;
const IOSETVBUF: i32 = 0x0400;
const TEMPORARY: i32 = 0x1000;
/// The buffer bits: a stream with none of them has no buffer yet.
const BUFFERED: i32 = IOMYBUF | IONBF | IOYOURBUF;

/// setvbuf's modes (`_IOLBF` is `_IOFBF` on Win32, MSDN says).
const IOFBF: i32 = 0x0000;
const IOLBF: i32 = 0x0040;

/// EOF.
const EOF: i32 = -1;

/// Each of `_iob`'s streams' lock (Windows 2000's per-stream lock): the C runtime changes the
/// stream's `FILE` only under it ([`with_stream`]).
static LOCKS: [Locked<(), Lock>; IOB_ENTRIES] =
    [const { Locked::new(Lock::new(), ()) }; IOB_ENTRIES];

/// The lock of a stream that is not one of `_iob`'s (a program's own `FILE`).
static OTHER: Locked<(), Lock> = Locked::new(Lock::new(), ());

/// The buffers lent to stdout and stderr for a call, each taken under its stream's lock.
static LENT: [Locked<[u8; STREAM_BUFFER], Lock>; 2] =
    [const { Locked::new(Lock::new(), [0; STREAM_BUFFER]) }; 2];

/// `_iob`'s stream `index`.
fn stream_at(index: usize) -> *mut File {
    IOB.get().cast::<File>().wrapping_add(index)
}

/// A stream's index in `_iob`, when it is one of them.
fn index_of(stream: *mut File) -> Option<usize> {
    let offset = (stream as usize).wrapping_sub(stream_at(0) as usize);
    let size = core::mem::size_of::<File>();
    (offset.is_multiple_of(size) && offset / size < IOB_ENTRIES).then_some(offset / size)
}

/// `body` run over `stream` with the stream's lock held, given its index in `_iob` (none for a
/// stream that is not one of them). It answers what `body` answers.
///
/// # Panics
///
/// When `body` reaches the same stream again through this function: its `FILE` is already lent.
///
/// # Safety
///
/// `stream` is a `FILE` that stays valid for the call: one of `_iob`'s, or one of the caller's.
unsafe fn with_stream<R>(stream: *mut File, body: impl FnOnce(&mut File, Option<usize>) -> R) -> R {
    let index = index_of(stream);
    index.map_or(&OTHER, |i| &LOCKS[i]).with(|()| {
        // SAFETY: the caller's stream, valid and aligned; under its lock, and the lock's busy flag
        // refuses a second `with`, so this is the C runtime's one reference to it until `body`
        // returns (a program touching `_iob` itself meanwhile breaks the C runtime's contract).
        body(unsafe { &mut *stream }, index)
    })
}

/// The stream's buffer given its own `STREAM_BUFFER` bytes, or (out of memory) none at all: its
/// one-character buffer.
fn give_buffer(s: &mut File) {
    let buffer = crate::heap::allocate(STREAM_BUFFER, false);
    if buffer.is_null() {
        s.flag |= IONBF;
        s.base = core::ptr::addr_of_mut!(s.charbuf).cast();
        s.bufsiz = 2;
    } else {
        s.flag |= IOMYBUF;
        s.base = buffer;
        s.bufsiz = STREAM_BUFFER as i32;
    }
    s.ptr = s.base;
    s.cnt = 0;
}

/// The stream's pending output written to its descriptor, its buffer emptied (`_cnt` 0); a
/// reading stream's buffered input dropped. 0, or EOF on a write error (`_IOERR`).
///
/// # Safety
///
/// The stream's `_base` and `_ptr` describe its buffer, as the C runtime keeps them.
unsafe fn flush(s: &mut File) -> i32 {
    let mut result = 0;
    if s.flag & (IOREAD | IOWRT) == IOWRT && s.flag & (IOMYBUF | IOYOURBUF) != 0 {
        let pending = (s.ptr as usize).wrapping_sub(s.base as usize) as i32;
        if pending > 0 {
            // SAFETY: the stream's buffer, its pending bytes.
            if unsafe { lowio::write(s.file, s.base, pending as u32) } == pending {
                if s.flag & IORW != 0 {
                    s.flag &= !IOWRT;
                }
            } else {
                s.flag |= IOERR;
                result = EOF;
            }
        }
    }
    s.ptr = s.base;
    s.cnt = 0;
    result
}

/// A character written through the stream's buffer when it is full, or has none yet (MSVC's
/// `_flsbuf`): the character, or EOF (`_IOERR`). `index` is the stream's in `_iob`.
///
/// # Safety
///
/// As [`flush`]'s.
unsafe fn flush_and_put(c: u8, s: &mut File, index: Option<usize>) -> i32 {
    if s.flag & (IOWRT | IORW) == 0 || s.flag & IOSTRG != 0 {
        s.flag |= IOERR;
        return EOF;
    }
    if s.flag & IOREAD != 0 {
        s.cnt = 0;
        if s.flag & IOEOF == 0 {
            s.flag |= IOERR;
            return EOF;
        }
        s.ptr = s.base;
        s.flag &= !IOREAD;
    }
    s.flag |= IOWRT;
    s.flag &= !IOEOF;
    s.cnt = 0;
    let fd = s.file;
    if s.flag & BUFFERED == 0 {
        let standard = matches!(index, Some(1 | 2));
        if !(standard && lowio::is_device(fd)) {
            give_buffer(s);
        }
    }
    let ok = if s.flag & (IOMYBUF | IOYOURBUF) != 0 {
        let pending = (s.ptr as usize).wrapping_sub(s.base as usize) as i32;
        s.ptr = s.base;
        let ok = pending <= 0
            // SAFETY: the stream's buffer, its pending bytes.
            || unsafe { lowio::write(fd, s.base, pending as u32) } == pending;
        // SAFETY: the buffer's first byte.
        unsafe { s.ptr.write(c) };
        // SAFETY: inside the buffer.
        s.ptr = unsafe { s.ptr.add(1) };
        s.cnt = s.bufsiz - 1;
        ok
    } else {
        // SAFETY: one byte.
        unsafe { lowio::write(fd, &c, 1) == 1 }
    };
    if !ok {
        s.flag |= IOERR;
        return EOF;
    }
    c as i32
}

/// A character written to the stream (`putc`).
///
/// # Safety
///
/// As [`flush`]'s, and `_cnt` counts the room left in the buffer.
unsafe fn put(c: u8, s: &mut File, index: Option<usize>) -> i32 {
    s.cnt -= 1;
    if s.cnt >= 0 {
        // SAFETY: inside the buffer: `_cnt` counted the room.
        unsafe {
            s.ptr.write(c);
            s.ptr = s.ptr.add(1);
        }
        return c as i32;
    }
    // SAFETY: as above.
    unsafe { flush_and_put(c, s, index) }
}

/// The stream's buffer refilled from its descriptor, its first character taken (MSVC's
/// `_filbuf`): the character, or EOF (`_IOEOF` at the end, `_IOERR` on an error).
///
/// # Safety
///
/// The stream's `_base` and `_bufsiz` describe its buffer, as the C runtime keeps them.
unsafe fn fill(s: &mut File) -> i32 {
    // A stream that cannot read, or is writing (a `+` stream switches through fflush).
    if s.flag & (IOREAD | IORW) == 0 || s.flag & (IOWRT | IOSTRG) != 0 {
        s.flag |= IOERR;
        return EOF;
    }
    s.flag |= IOREAD;
    if s.flag & BUFFERED == 0 {
        give_buffer(s);
    } else {
        s.ptr = s.base;
    }
    // SAFETY: the stream's buffer.
    let count = unsafe { lowio::read(s.file, s.base, s.bufsiz as usize) };
    if count <= 0 {
        s.flag |= if count == 0 { IOEOF } else { IOERR };
        s.cnt = 0;
        return EOF;
    }
    s.cnt = count - 1;
    // SAFETY: inside the bytes read.
    unsafe {
        let c = s.ptr.read();
        s.ptr = s.ptr.add(1);
        c as i32
    }
}

/// A character read from the stream (`getc`).
///
/// # Safety
///
/// As [`fill`]'s, and `_ptr` and `_cnt` describe the bytes left in the buffer.
unsafe fn get(s: &mut File) -> i32 {
    s.cnt -= 1;
    if s.cnt >= 0 {
        // SAFETY: inside the bytes buffered.
        unsafe {
            let c = s.ptr.read();
            s.ptr = s.ptr.add(1);
            return c as i32;
        }
    }
    // SAFETY: as above.
    unsafe { fill(s) }
}

/// Every stream writing flushed, each under its own lock in turn; EOF when one failed.
pub fn flush_all() -> i32 {
    let mut result = 0;
    for i in 0..IOB_ENTRIES {
        let writing = |s: &mut File, _| {
            if s.flag & (IOWRT | IORW) != 0 && s.flag & IOREAD == 0 {
                // SAFETY: the stream's buffer as the C runtime keeps it.
                unsafe { flush(s) }
            } else {
                0
            }
        };
        // SAFETY: one of `_iob`'s streams.
        if unsafe { with_stream(stream_at(i), writing) } == EOF {
            result = EOF;
        }
    }
    result
}

/// A stream the formatter writes to, under its lock: its `FILE` and its index in `_iob`.
struct Stream<'a> {
    file: &'a mut File,
    index: Option<usize>,
}

impl Output for Stream<'_> {
    fn put(&mut self, unit: u32) {
        // SAFETY: the stream's buffer as the C runtime keeps it.
        unsafe { put(unit as u8, self.file, self.index) };
    }
}

/// Formatted output to a stream, under its lock: stdout or stderr on a device lent a buffer for
/// the call and flushed at its end. The count, or -1 when a write failed.
///
/// # Safety
///
/// `stream` is a stream; `text` and `args` are the formatter's.
unsafe fn print(stream: *mut File, text: *const u8, args: &mut impl Args) -> i32 {
    let body = |s: &mut File, index| match index {
        Some(i @ (1 | 2)) if s.flag & BUFFERED == 0 && lowio::is_device(s.file) => {
            LENT[i - 1].with(|buffer| {
                s.base = buffer.as_mut_ptr();
                s.ptr = s.base;
                s.cnt = STREAM_BUFFER as i32;
                s.bufsiz = STREAM_BUFFER as i32;
                s.flag |= IOWRT | IOYOURBUF | TEMPORARY;
                // SAFETY: the caller's format and arguments; the stream's buffer is the lent one,
                // taken back from the stream before the lent buffer's lock is let go.
                unsafe { format_to(s, index, text, args, true) }
            })
        }
        // SAFETY: the caller's format and arguments.
        _ => unsafe { format_to(s, index, text, args, false) },
    };
    // SAFETY: the caller's stream.
    unsafe { with_stream(stream, body) }
}

/// [`print`]'s formatting into the stream, its `_IOERR` the call's own: a buffer `lent` for the
/// call flushed and taken back at its end.
///
/// # Safety
///
/// `text` and `args` are the formatter's; the stream's buffer is as the C runtime keeps it.
unsafe fn format_to(
    s: &mut File,
    index: Option<usize>,
    text: *const u8,
    args: &mut impl Args,
    lent: bool,
) -> i32 {
    let errors = s.flag & IOERR;
    s.flag &= !IOERR;
    // SAFETY: the caller's format and arguments.
    let count = unsafe { format::format(text, args, &mut Stream { file: s, index }) };
    if lent {
        // SAFETY: the lent buffer, its pending bytes.
        unsafe { flush(s) };
        s.base = core::ptr::null_mut();
        s.ptr = core::ptr::null_mut();
        s.cnt = 0;
        s.bufsiz = 0;
        s.flag &= !(IOYOURBUF | TEMPORARY);
    }
    let failed = s.flag & IOERR != 0;
    s.flag |= errors;
    if failed {
        -1
    } else {
        count as i32
    }
}

/// printf's body: the format and its arguments to stdout.
///
/// # Safety
///
/// `text` is NUL-terminated, `args` the caller's arguments for it.
pub unsafe extern "C" fn printf_va(text: *const u8, args: *const u8) -> i32 {
    // SAFETY: the caller's contract; stdout is `_iob[1]`.
    unsafe { print(stream_at(1), text, &mut VaList(args)) }
}

/// fprintf's body.
///
/// # Safety
///
/// `stream` is a stream; the rest as printf_va's.
pub unsafe extern "C" fn fprintf_va(stream: *mut File, text: *const u8, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { print(stream, text, &mut VaList(args)) }
}

/// sprintf's body: the text and its NUL into `buffer`.
///
/// # Safety
///
/// `buffer` has room for the text; the rest as printf_va's.
pub unsafe extern "C" fn sprintf_va(buffer: *mut u8, text: *const u8, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { format::unbounded(buffer, text, &mut VaList(args)) }
}

/// _vsnprintf: at most `count` bytes into `buffer` (see [`format::bounded`]).
///
/// # Safety
///
/// `buffer` holds `count` bytes; `text` is NUL-terminated; `args` is the caller's `va_list`.
#[unsafe(export_name = "f2k_export__vsnprintf")]
pub unsafe extern "C" fn vsnprintf(
    buffer: *mut u8,
    count: usize,
    text: *const u8,
    args: *const u8,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { format::bounded(buffer, count, text, &mut VaList(args)) }
}

/// swprintf's body (MSVC 6's swprintf takes no count).
///
/// # Safety
///
/// As sprintf_va's, in wide units.
pub unsafe extern "C" fn swprintf_va(buffer: *mut u16, text: *const u16, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { format::unbounded(buffer, text, &mut VaList(args)) }
}

/// _snwprintf's body.
///
/// # Safety
///
/// As _vsnprintf's, in wide units.
pub unsafe extern "C" fn snwprintf_va(
    buffer: *mut u16,
    count: usize,
    text: *const u16,
    args: *const u8,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { format::bounded(buffer, count, text, &mut VaList(args)) }
}

/// _vsnwprintf: at most `count` wide units into `buffer`.
///
/// # Safety
///
/// As _vsnprintf's, in wide units.
#[unsafe(export_name = "f2k_export__vsnwprintf")]
pub unsafe extern "C" fn vsnwprintf(
    buffer: *mut u16,
    count: usize,
    text: *const u16,
    args: *const u8,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { format::bounded(buffer, count, text, &mut VaList(args)) }
}

/// swscanf's body.
///
/// # Safety
///
/// `input` and `text` are NUL-terminated; `args` holds the pointers its fields store through.
pub unsafe extern "C" fn swscanf_va(input: *const u16, text: *const u16, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { crate::scan::scan(input, text, &mut VaList(args)) }
}

/// The exports taking variable arguments: each hands its fixed arguments and the address of its
/// variable ones (where its caller pushed them, cdecl) to its body.
#[cfg(target_arch = "x86")]
mod variadic {
    use super::*;

    /// printf(format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export_printf")]
    pub unsafe extern "C" fn printf() {
        core::arch::naked_asm!(
            "lea eax, [esp+8]",
            "push eax",
            "push dword ptr [esp+8]",
            "call {body}",
            "add esp, 8",
            "ret",
            body = sym printf_va,
        )
    }

    /// fprintf(stream, format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export_fprintf")]
    pub unsafe extern "C" fn fprintf() {
        core::arch::naked_asm!(
            "lea eax, [esp+12]",
            "push eax",
            "push dword ptr [esp+12]",
            "push dword ptr [esp+12]",
            "call {body}",
            "add esp, 12",
            "ret",
            body = sym fprintf_va,
        )
    }

    /// sprintf(buffer, format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export_sprintf")]
    pub unsafe extern "C" fn sprintf() {
        core::arch::naked_asm!(
            "lea eax, [esp+12]",
            "push eax",
            "push dword ptr [esp+12]",
            "push dword ptr [esp+12]",
            "call {body}",
            "add esp, 12",
            "ret",
            body = sym sprintf_va,
        )
    }

    /// swprintf(buffer, format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export_swprintf")]
    pub unsafe extern "C" fn swprintf() {
        core::arch::naked_asm!(
            "lea eax, [esp+12]",
            "push eax",
            "push dword ptr [esp+12]",
            "push dword ptr [esp+12]",
            "call {body}",
            "add esp, 12",
            "ret",
            body = sym swprintf_va,
        )
    }

    /// _snwprintf(buffer, count, format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export__snwprintf")]
    pub unsafe extern "C" fn snwprintf() {
        core::arch::naked_asm!(
            "lea eax, [esp+16]",
            "push eax",
            "push dword ptr [esp+16]",
            "push dword ptr [esp+16]",
            "push dword ptr [esp+16]",
            "call {body}",
            "add esp, 16",
            "ret",
            body = sym snwprintf_va,
        )
    }

    /// swscanf(input, format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export_swscanf")]
    pub unsafe extern "C" fn swscanf() {
        core::arch::naked_asm!(
            "lea eax, [esp+12]",
            "push eax",
            "push dword ptr [esp+12]",
            "push dword ptr [esp+12]",
            "call {body}",
            "add esp, 12",
            "ret",
            body = sym swscanf_va,
        )
    }
}

/// fflush: the stream's pending output written (every writing stream's for NULL); 0 or EOF.
///
/// # Safety
///
/// `stream` is null or a stream.
#[unsafe(export_name = "f2k_export_fflush")]
pub unsafe extern "C" fn fflush(stream: *mut File) -> i32 {
    if stream.is_null() {
        return flush_all();
    }
    // SAFETY: the stream's buffer as the C runtime keeps it.
    let body = |s: &mut File, _| unsafe { flush(s) };
    // SAFETY: the caller's stream.
    unsafe { with_stream(stream, body) }
}

/// fgets: a line (its newline kept), at most `n - 1` bytes, NUL-terminated into `buffer`; NULL at
/// the end before any byte, or on an error. The stream's lock is held across its reads.
///
/// # Safety
///
/// `buffer` holds `n` bytes; `stream` is a stream.
#[unsafe(export_name = "f2k_export_fgets")]
pub unsafe extern "C" fn fgets(buffer: *mut u8, n: i32, stream: *mut File) -> *mut u8 {
    if n <= 0 || stream.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller's buffer of `n` bytes.
    let out = unsafe { core::slice::from_raw_parts_mut(buffer, n as usize) };
    let body = |s: &mut File, _| {
        let mut length = 0usize;
        while length + 1 < out.len() {
            // SAFETY: the stream's buffer as the C runtime keeps it.
            let c = unsafe { get(s) };
            if c == EOF {
                if length == 0 {
                    return false;
                }
                break;
            }
            out[length] = c as u8;
            length += 1;
            if c == b'\n' as i32 {
                break;
            }
        }
        out[length] = 0;
        true
    };
    // SAFETY: the caller's stream.
    if unsafe { with_stream(stream, body) } {
        buffer
    } else {
        core::ptr::null_mut()
    }
}

/// The stream's own buffer freed.
///
/// # Safety
///
/// The stream's `_base` is its own buffer's when it has `_IOMYBUF`.
unsafe fn free_buffer(s: &mut File) {
    if s.flag & IOMYBUF != 0 {
        // SAFETY: the stream's own buffer.
        unsafe { crate::heap::release(s.base) };
    }
    s.flag &= !(IOMYBUF | IOSETVBUF);
    s.base = core::ptr::null_mut();
    s.ptr = core::ptr::null_mut();
    s.cnt = 0;
}

/// fclose: the stream flushed, its buffer freed, its descriptor closed; 0, or EOF.
///
/// # Safety
///
/// `stream` is a stream.
#[unsafe(export_name = "f2k_export_fclose")]
pub unsafe extern "C" fn fclose(stream: *mut File) -> i32 {
    let body = |s: &mut File, _| {
        if s.flag & IOSTRG != 0 || s.flag & (IOREAD | IOWRT | IORW) == 0 {
            s.flag = 0;
            return EOF;
        }
        // SAFETY: the stream's buffer and temporary name as the C runtime keeps them.
        unsafe {
            let mut result = flush(s);
            free_buffer(s);
            if lowio::close(s.file) < 0 {
                result = EOF;
            }
            if !s.tmpfname.is_null() {
                crate::heap::release(s.tmpfname);
            }
            *s = File::UNUSED;
            result
        }
    };
    // SAFETY: the caller's stream.
    unsafe { with_stream(stream, body) }
}

/// setvbuf: the stream's buffering: `mode` `_IOFBF` (or `_IOLBF`, the same) with the caller's
/// buffer of `size` bytes, or one of the stream's own when it is NULL; `_IONBF` none. 0, or -1 for
/// a bad mode or size.
///
/// # Safety
///
/// `stream` is a stream; `buffer` is null or holds `size` bytes for the stream's life.
#[unsafe(export_name = "f2k_export_setvbuf")]
pub unsafe extern "C" fn setvbuf(
    stream: *mut File,
    buffer: *mut u8,
    mode: i32,
    size: usize,
) -> i32 {
    if mode != IONBF && (mode != IOFBF && mode != IOLBF || !(2..=i32::MAX as usize).contains(&size))
    {
        return -1;
    }
    let body = |s: &mut File, _| {
        // SAFETY: the stream's buffer as the C runtime keeps it.
        unsafe {
            flush(s);
            free_buffer(s);
        }
        s.flag &= !(IOMYBUF | IOYOURBUF | IONBF | IOSETVBUF | TEMPORARY);
        let (base, size) = if mode == IONBF {
            s.flag |= IONBF;
            (core::ptr::addr_of_mut!(s.charbuf).cast::<u8>(), 2)
        } else if buffer.is_null() {
            let own = crate::heap::allocate(size, false);
            if own.is_null() {
                return -1;
            }
            s.flag |= IOMYBUF | IOSETVBUF;
            (own, size)
        } else {
            s.flag |= IOYOURBUF | IOSETVBUF;
            (buffer, size)
        };
        s.base = base;
        s.ptr = base;
        s.bufsiz = size as i32;
        s.cnt = 0;
        0
    };
    // SAFETY: the caller's stream.
    unsafe { with_stream(stream, body) }
}

/// _fdopen: a stream over descriptor `fd`, reading (`r`), writing (`w`, `a`) or both (`+`); the
/// translation stays the descriptor's. NULL for a bad mode (EINVAL), a descriptor not open
/// (EBADF), or no free stream (EMFILE). Each stream is looked at, and claimed when free, under its
/// own lock.
///
/// # Safety
///
/// `mode` is NUL-terminated.
#[unsafe(export_name = "f2k_export__fdopen")]
pub unsafe extern "C" fn fdopen(fd: i32, mode: *const u8) -> *mut File {
    // SAFETY: the caller's mode string.
    let mode = unsafe { core::ffi::CStr::from_ptr(mode.cast()) }.to_bytes();
    let mut flag = match mode.first() {
        Some(b'r') => IOREAD,
        Some(b'w' | b'a') => IOWRT,
        _ => {
            set_errno(EINVAL);
            return core::ptr::null_mut();
        }
    };
    if mode[1..].contains(&b'+') {
        flag = IORW;
    }
    if lowio::get_osfhandle(fd) == -1 {
        set_errno(EBADF);
        return core::ptr::null_mut();
    }
    for i in 0..IOB_ENTRIES {
        let claim = |s: &mut File, _| {
            let free = s.flag & (IOREAD | IOWRT | IORW) == 0;
            if free {
                *s = File {
                    flag,
                    file: fd,
                    ..File::UNUSED
                };
            }
            free
        };
        // SAFETY: one of `_iob`'s streams.
        if unsafe { with_stream(stream_at(i), claim) } {
            return stream_at(i);
        }
    }
    set_errno(EMFILE);
    core::ptr::null_mut()
}
