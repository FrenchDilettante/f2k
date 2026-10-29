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
//!
//! An export converts its `FILE *` once ([`with_stream`]), under the stream's lock; the work below
//! is over the `&mut File` it lends. An exception that unwinds out of a call (a fault in a
//! caller's string or buffer, taken by the program's `__except`) lets the stream's lock go, and a
//! buffer lent for the call is given back first, its bytes written, as the call's end would have.

use rtl::cstr::bytes_until_nul;
use rtl::sync::Locked;

use crate::data::{File, IOB, IOB_ENTRIES, STREAM_BUFFER};
use crate::edge::{self, WideUnit};
use crate::format::{self, Args, Output, Unbounded, VaList};
use crate::lowio;
use crate::thread::{set_errno, UnwindLock, EBADF, EINVAL, EMFILE};
use crate::unwind;

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
static LOCKS: [Locked<(), UnwindLock>; IOB_ENTRIES] =
    [const { Locked::new(UnwindLock::new(), ()) }; IOB_ENTRIES];

/// The lock of a stream that is not one of `_iob`'s (a program's own `FILE`).
static OTHER: Locked<(), UnwindLock> = Locked::new(UnwindLock::new(), ());

/// The buffers lent to stdout and stderr for a call, each taken under its stream's lock.
static LENT: [Locked<[u8; STREAM_BUFFER], UnwindLock>; 2] =
    [const { Locked::new(UnwindLock::new(), [0; STREAM_BUFFER]) }; 2];

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
/// stream that is not one of them). It answers what `body` answers. The lock is let go when
/// `body` returns, or when an exception unwinds out of it.
///
/// The `&mut File` lent is the one place the C runtime forms one, and the functions below rely on
/// what a `FILE` the C runtime keeps holds: its `_base`, `_bufsiz`, `_ptr` and `_cnt` describe its
/// buffer (the stream's own, one lent for the call, or one setvbuf was given for the stream's
/// life), as the getc and putc macros programs inline keep them too.
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

/// [`with_stream`] over `_iob`'s stream `index`.
fn with_iob<R>(index: usize, body: impl FnOnce(&mut File, Option<usize>) -> R) -> R {
    // SAFETY: one of `_iob`'s streams, the DLL's own for the process's life.
    unsafe { with_stream(stream_at(index), body) }
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

/// The bytes the stream's buffer holds before `_ptr` (the output it has pending), as an `i32`
/// count: none when `_ptr` is not past `_base`.
fn pending(s: &File) -> (i32, &[u8]) {
    let count = (s.ptr as usize).wrapping_sub(s.base as usize) as i32;
    if count <= 0 {
        return (count, &[]);
    }
    // SAFETY: a `FILE` the C runtime keeps (see `with_stream`): `_base` to `_ptr` is inside its
    // buffer, and the stream's lock keeps it the call's.
    (count, unsafe {
        core::slice::from_raw_parts(s.base, count as usize)
    })
}

/// The stream's pending output written to its descriptor, its buffer emptied (`_cnt` 0); a
/// reading stream's buffered input dropped. 0, or EOF on a write error (`_IOERR`).
fn flush(s: &mut File) -> i32 {
    let mut result = 0;
    if s.flag & (IOREAD | IOWRT) == IOWRT && s.flag & (IOMYBUF | IOYOURBUF) != 0 {
        let (count, bytes) = pending(s);
        if count > 0 {
            if lowio::write(s.file, bytes) == count {
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

/// `c` stored at the stream's `_ptr`, which moves past it.
fn store(s: &mut File, c: u8) {
    // SAFETY: a `FILE` the C runtime keeps (see `with_stream`), and the callers' check: `_ptr` is
    // inside its buffer, with room for the byte.
    unsafe {
        s.ptr.write(c);
        s.ptr = s.ptr.add(1);
    }
}

/// The byte at the stream's `_ptr`, which moves past it.
fn take(s: &mut File) -> u8 {
    // SAFETY: a `FILE` the C runtime keeps (see `with_stream`), and the callers' check: `_ptr` is
    // inside the bytes its buffer holds.
    unsafe {
        let c = s.ptr.read();
        s.ptr = s.ptr.add(1);
        c
    }
}

/// A character written through the stream's buffer when it is full, or has none yet (MSVC's
/// `_flsbuf`): the character, or EOF (`_IOERR`). `index` is the stream's in `_iob`.
fn flush_and_put(c: u8, s: &mut File, index: Option<usize>) -> i32 {
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
        let (count, bytes) = pending(s);
        let ok = count <= 0 || lowio::write(fd, bytes) == count;
        s.ptr = s.base;
        // The buffer's first byte.
        store(s, c);
        s.cnt = s.bufsiz - 1;
        ok
    } else {
        lowio::write(fd, &[c]) == 1
    };
    if !ok {
        s.flag |= IOERR;
        return EOF;
    }
    c as i32
}

/// A character written to the stream (`putc`).
fn put(c: u8, s: &mut File, index: Option<usize>) -> i32 {
    s.cnt -= 1;
    if s.cnt >= 0 {
        // `_cnt` counted the room.
        store(s, c);
        return c as i32;
    }
    flush_and_put(c, s, index)
}

/// The stream's buffer refilled from its descriptor, its first character taken (MSVC's
/// `_filbuf`): the character, or EOF (`_IOEOF` at the end, `_IOERR` on an error).
fn fill(s: &mut File) -> i32 {
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
    // SAFETY: a `FILE` the C runtime keeps (see `with_stream`): its buffer, `_bufsiz` bytes at
    // `_base`, which the stream's lock keeps the call's.
    let buffer = unsafe { core::slice::from_raw_parts_mut(s.base, s.bufsiz as usize) };
    let count = lowio::read(s.file, buffer);
    if count <= 0 {
        s.flag |= if count == 0 { IOEOF } else { IOERR };
        s.cnt = 0;
        return EOF;
    }
    s.cnt = count - 1;
    // Inside the bytes read.
    take(s) as i32
}

/// A character read from the stream (`getc`).
fn get(s: &mut File) -> i32 {
    s.cnt -= 1;
    if s.cnt >= 0 {
        // `_cnt` counted the bytes buffered.
        return take(s) as i32;
    }
    fill(s)
}

/// Every stream writing flushed, each under its own lock in turn; EOF when one failed.
pub fn flush_all() -> i32 {
    let mut result = 0;
    for i in 0..IOB_ENTRIES {
        let writing = |s: &mut File, _| {
            if s.flag & (IOWRT | IORW) != 0 && s.flag & IOREAD == 0 {
                flush(s)
            } else {
                0
            }
        };
        if with_iob(i, writing) == EOF {
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
        put(unit as u8, self.file, self.index);
    }
}

/// The buffer stdout or stderr is lent for a call, given to the stream.
fn lend(s: &mut File, buffer: &mut [u8; STREAM_BUFFER]) {
    s.base = buffer.as_mut_ptr();
    s.ptr = s.base;
    s.cnt = STREAM_BUFFER as i32;
    s.bufsiz = STREAM_BUFFER as i32;
    s.flag |= IOWRT | IOYOURBUF | TEMPORARY;
}

/// The buffer lent for a call taken back from the stream, its bytes written first.
fn give_back(s: &mut File) {
    flush(s);
    s.base = core::ptr::null_mut();
    s.ptr = core::ptr::null_mut();
    s.cnt = 0;
    s.bufsiz = 0;
    s.flag &= !(IOYOURBUF | TEMPORARY);
}

/// Formatted output to a stream, under its lock: stdout or stderr on a device lent a buffer for
/// the call and flushed at its end. The count, or -1 when a write failed (the call's `_IOERR`,
/// the stream's own kept apart). An exception unwinding out of the formatting ends the call as its
/// end would: the lent buffer given back, its bytes written, and the stream's `_IOERR` as it was.
///
/// # Safety
///
/// `stream` is a stream; `args` holds what `text`'s conversions consume.
unsafe fn print(stream: *mut File, text: &[u8], args: &mut impl Args) -> i32 {
    let body = |s: &mut File, index: Option<usize>| {
        let lent = match index {
            Some(i @ (1 | 2)) if s.flag & BUFFERED == 0 && lowio::is_device(s.file) => {
                Some(&LENT[i - 1])
            }
            _ => None,
        };
        let mut format_into = |s: &mut File| {
            let errors = s.flag & IOERR;
            s.flag &= !IOERR;
            // The call's end: the lent buffer given back, and whether a write failed.
            let finish = |s: &mut File| {
                if lent.is_some() {
                    give_back(s);
                }
                let failed = s.flag & IOERR != 0;
                s.flag |= errors;
                failed
            };
            let abandon = || {
                // SAFETY: run only as an exception unwinds out of the formatting below. The
                // `&mut File` it was lent is abandoned with its frames, never used again; the
                // stream's lock (and the lent buffer's), still this thread's until the frames
                // outside this one let them go, keep every other thread from the stream.
                finish(unsafe { &mut *stream });
            };
            let count = unwind::on_unwind(&abandon, || {
                format::format(text, args, &mut Stream { file: s, index })
            });
            if finish(s) {
                -1
            } else {
                count as i32
            }
        };
        match lent {
            Some(lent) => lent.with(|buffer| {
                lend(s, buffer);
                format_into(s)
            }),
            None => format_into(s),
        }
    };
    // SAFETY: the caller's stream.
    unsafe { with_stream(stream, body) }
}

/// printf's body: the format and its arguments to stdout.
///
/// # Safety
///
/// `text` is NUL-terminated, `args` the caller's arguments for it.
pub unsafe extern "C" fn printf_va(text: *const u8, args: *const u8) -> i32 {
    // SAFETY: the caller's contract; stdout is `_iob[1]`.
    unsafe { print(stream_at(1), bytes_until_nul(text), &mut VaList::new(args)) }
}

/// fprintf's body.
///
/// # Safety
///
/// `stream` is a stream; the rest as printf_va's.
pub unsafe extern "C" fn fprintf_va(stream: *mut File, text: *const u8, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { print(stream, bytes_until_nul(text), &mut VaList::new(args)) }
}

/// sprintf's body: the text and its NUL into `buffer`.
///
/// # Safety
///
/// `buffer` has room for the text; the rest as printf_va's.
pub unsafe extern "C" fn sprintf_va(buffer: *mut u8, text: *const u8, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe {
        format::unbounded(
            Unbounded::new(buffer),
            bytes_until_nul(text),
            &mut VaList::new(args),
        )
    }
}

/// The caller's buffer of `count` units, as the bounded formatters write it.
///
/// # Safety
///
/// `buffer` holds `count` units (of any alignment), the call's alone.
unsafe fn units_out<'a, U>(buffer: *mut U, count: usize) -> &'a mut [U] {
    if count == 0 {
        return &mut [];
    }
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts_mut(buffer, count) }
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
    unsafe {
        format::bounded(
            units_out(buffer, count),
            bytes_until_nul(text),
            &mut VaList::new(args),
        )
    }
}

/// swprintf's body (MSVC 6's swprintf takes no count).
///
/// # Safety
///
/// As sprintf_va's, in wide units.
pub unsafe extern "C" fn swprintf_va(buffer: *mut u16, text: *const u16, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe {
        format::unbounded(
            Unbounded::new(buffer.cast::<WideUnit>()),
            edge::wide(text),
            &mut VaList::new(args),
        )
    }
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
    unsafe { vsnwprintf(buffer, count, text, args) }
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
    unsafe {
        format::bounded(
            units_out(buffer.cast::<WideUnit>(), count),
            edge::wide(text),
            &mut VaList::new(args),
        )
    }
}

/// swscanf's body.
///
/// # Safety
///
/// `input` and `text` are NUL-terminated; `args` holds the pointers its fields store through.
pub unsafe extern "C" fn swscanf_va(input: *const u16, text: *const u16, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { crate::scan::scan(edge::wide(input), edge::wide(text), &mut VaList::new(args)) }
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
    // SAFETY: the caller's stream.
    unsafe { with_stream(stream, |s, _| flush(s)) }
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
            let c = get(s);
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
fn free_buffer(s: &mut File) {
    if s.flag & IOMYBUF != 0 {
        // SAFETY: a `FILE` the C runtime keeps (see `with_stream`): with `_IOMYBUF`, `_base` is
        // the stream's own block of the C runtime's heap, forgotten below.
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
        let mut result = flush(s);
        free_buffer(s);
        if lowio::close(s.file) < 0 {
            result = EOF;
        }
        if !s.tmpfname.is_null() {
            // SAFETY: a `FILE` the C runtime keeps: its temporary name is a block of the C
            // runtime's heap, forgotten below.
            unsafe { crate::heap::release(s.tmpfname) };
        }
        *s = File::UNUSED;
        result
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
        flush(s);
        free_buffer(s);
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
    let mode = unsafe { bytes_until_nul(mode) };
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
        if with_iob(i, claim) {
            return stream_at(i);
        }
    }
    set_errno(EMFILE);
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Arguments whose string faults when the formatter reads it (on the host, a panic stands in
    /// for the exception).
    struct Faulting;

    // SAFETY: it hands out no pointer.
    unsafe impl Args for Faulting {
        fn int(&mut self) -> u32 {
            0
        }

        fn quad(&mut self) -> u64 {
            0
        }

        fn double(&mut self) -> f64 {
            0.0
        }

        fn pointer(&mut self) -> usize {
            panic!("a fault in the caller's string")
        }
    }

    /// An exception unwinding out of fprintf (a `%s` over a bad pointer, taken by the program's
    /// `__except`) leaves the stream as the call's end would and its lock let go: the output
    /// before the fault buffered, the stream's `_IOERR` as it was; the same thread's next call on
    /// the stream goes ahead, and so does another thread's.
    #[test]
    fn an_unwind_out_of_a_print_lets_the_stream_go() {
        let mut buffer = [0u8; 16];
        let mut file = File {
            base: buffer.as_mut_ptr(),
            ptr: buffer.as_mut_ptr(),
            cnt: 16,
            bufsiz: 16,
            flag: IOWRT | IOYOURBUF | IOERR,
            file: 2000,
            ..File::UNUSED
        };
        let address = core::ptr::addr_of_mut!(file) as usize;
        let unwound = std::panic::catch_unwind(|| {
            // SAFETY: the test's stream, its buffer the test's.
            unsafe { print(address as *mut File, b"ab%sc", &mut Faulting) }
        });
        assert!(unwound.is_err());
        // SAFETY: the test's stream, taken again on the same thread.
        let (count, flag) =
            unsafe { with_stream(address as *mut File, |s, _| (pending(s).0, s.flag)) };
        assert_eq!((count, flag & IOERR), (2, IOERR));
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // SAFETY: the test's stream, which outlives the wait below.
            let flag = unsafe { with_stream(address as *mut File, |s, _| s.flag) };
            sender.send(flag).unwrap();
        });
        let taken = receiver.recv_timeout(std::time::Duration::from_secs(10));
        assert!(taken.is_ok(), "another thread takes the stream's lock");
        assert_eq!(&buffer[..2], b"ab");
    }
}
