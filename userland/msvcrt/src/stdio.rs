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
//! - fread and fwrite move bytes through the buffer, as getc and putc do, and answer the items
//!   moved whole. ftell counts the file's bytes: in text mode each LF the buffer still holds, or
//!   has pending, counts as the CR LF it is in the file (MSDN's ftell: only fseek need take the
//!   value back). fseek writes what is pending, drops what is buffered, clears the end of the file
//!   (the descriptor's Ctrl-Z too), and leaves a `+` stream free to read or write next; clearerr
//!   clears the end-of-file and error indicators alone.
//! - `_popen`'s streams ([`crate::process`]) are streams over a pipe's end like any other.
//!
//! wprintf and fwprintf write each wide character as MSDN's "Unicode Stream I/O in Text and Binary
//! Modes" says: on a text-mode descriptor converted as wctomb converts it (the LC_CTYPE locale's
//! code page; one it lacks fails the call: -1, errno EILSEQ), on a binary one as its two bytes.
//! fputws writes the same way (-1 for a character the code page lacks), and fgetws reads the
//! same way back: a byte per character in text mode, as mbtowc reads it, two in binary mode.
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

use crate::ctype;
use crate::data::{File, IOB, IOB_ENTRIES, STREAM_BUFFER};
use crate::edge::{self, WideUnit};
use crate::format::{self, Args, Output, Unbounded, VaList};
use crate::lowio;
use crate::thread::{set_errno, Lock, UnwindLock, EBADF, EILSEQ, EINVAL, EMFILE};
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

/// Each of `_iob`'s streams' lock (Windows 2000's per-stream lock, a critical section): the C
/// runtime changes the stream's `FILE` only under it ([`with_stream`]). A bare [`Lock`], taken
/// through [`Lock::holding`] (let go when an exception unwinds out of the call), not a `Locked`
/// value: its holder may take it again, as Windows 2000's critical section lets it.
static LOCKS: [Lock; IOB_ENTRIES] = [const { Lock::new() }; IOB_ENTRIES];

/// The lock of a stream that is not one of `_iob`'s (a program's own `FILE`).
static OTHER: Lock = Lock::new();

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
/// The lock is recursive for its holder, as Windows 2000's is: a call faulting in its caller's
/// memory holds its stream while the exception's filters run, and a program's `__except` filter
/// that prints on the same stream (the seh fixture's filterprint) goes ahead, its output after
/// what the faulting call had buffered. The C runtime's own code never takes a stream it already
/// holds.
///
/// # Safety
///
/// `stream` is a `FILE` that stays valid for the call: one of `_iob`'s, or one of the caller's.
unsafe fn with_stream<R>(stream: *mut File, body: impl FnOnce(&mut File, Option<usize>) -> R) -> R {
    let index = index_of(stream);
    index.map_or(&OTHER, |i| &LOCKS[i]).holding(|| {
        // SAFETY: the caller's stream, valid and aligned, under its lock: no other thread has a
        // reference to it until `body` returns (a program touching `_iob` itself meanwhile breaks
        // the C runtime's contract). The holder takes the lock again only from code an exception
        // runs on top of an interrupted call (a filter): this second `&mut File` aliases the
        // interrupted call's, which the exception stopped between two of its instructions — the
        // one place the C runtime breaks the rule, as Windows 2000's does, by the documented
        // re-entry of its critical section. The interrupted call never runs again when the filter
        // picks the handler (its frames are unwound); a filter that continues the execution
        // resumes it over whatever the filter's call left in the `FILE`.
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

/// Formatted output to a stream ([`output`]): the count, or -1 when a write failed.
///
/// # Safety
///
/// `stream` is a stream; `args` holds what `text`'s conversions consume.
unsafe fn print(stream: *mut File, text: &[u8], args: &mut impl Args) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { output(stream, |out| format::format(text, args, out)) }
}

/// A stream the wide formatter writes to, each wide character as its descriptor's mode takes it
/// (MSDN's "Unicode Stream I/O in Text and Binary Modes"). In text mode, the character in the
/// LC_CTYPE locale's code page, as wctomb converts it (its `\n` translated when the bytes go out);
/// a character the code page lacks fails the call, and nothing more is written. In binary mode,
/// the character's two bytes as they are, low first.
struct WideStream<'s, 'a> {
    stream: &'s mut Stream<'a>,
    text: bool,
    unconverted: bool,
}

impl Output for WideStream<'_, '_> {
    fn put(&mut self, unit: u32) {
        if self.unconverted {
            return;
        }
        let Stream { file, index } = &mut *self.stream;
        if !self.text {
            for byte in (unit as u16).to_le_bytes() {
                put(byte, file, *index);
            }
            return;
        }
        match ctype::wide_to_byte(unit as u16) {
            Some(byte) => {
                put(byte, file, *index);
            }
            None => self.unconverted = true,
        }
    }
}

/// Wide formatted output to a stream ([`output`]): the count of wide characters, or -1 when a write
/// failed, or with errno EILSEQ when a character has no form in the locale's code page.
///
/// # Safety
///
/// As [`print`]'s.
unsafe fn wide_print(stream: *mut File, text: &[WideUnit], args: &mut impl Args) -> i32 {
    let mut unconverted = false;
    // SAFETY: the caller's contract.
    let count = unsafe {
        output(stream, |out| {
            let text_mode = lowio::is_text(out.file.file);
            let mut wide = WideStream {
                stream: out,
                text: text_mode,
                unconverted: false,
            };
            let count = format::format(text, args, &mut wide);
            unconverted = wide.unconverted;
            count
        })
    };
    if unconverted {
        set_errno(EILSEQ);
        return -1;
    }
    count
}

/// wprintf's body: the wide format and its arguments to stdout.
///
/// # Safety
///
/// `text` is NUL-terminated, `args` the caller's arguments for it.
pub unsafe extern "C" fn wprintf_va(text: *const u16, args: *const u8) -> i32 {
    // SAFETY: the caller's contract; stdout is `_iob[1]`.
    unsafe { wide_print(stream_at(1), edge::wide(text), &mut VaList::new(args)) }
}

/// fwprintf's body.
///
/// # Safety
///
/// `stream` is a stream; the rest as wprintf_va's.
pub unsafe extern "C" fn fwprintf_va(stream: *mut File, text: *const u16, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { wide_print(stream, edge::wide(text), &mut VaList::new(args)) }
}

/// A call's output to a stream, `emit`'s, under the stream's lock: stdout or stderr on a device
/// lent a buffer for the call and flushed at its end. What `emit` counted, or -1 when a write
/// failed (the call's `_IOERR`, the stream's own kept apart). An exception unwinding out of `emit`
/// (a fault in the caller's memory it reads) ends the call as its end would: the lent buffer given
/// back, its bytes written, and the stream's `_IOERR` as it was.
///
/// # Safety
///
/// `stream` is a stream.
unsafe fn output(stream: *mut File, emit: impl FnOnce(&mut Stream<'_>) -> usize) -> i32 {
    let body = |s: &mut File, index: Option<usize>| {
        let lent = match index {
            Some(i @ (1 | 2)) if s.flag & BUFFERED == 0 && lowio::is_device(s.file) => {
                Some(&LENT[i - 1])
            }
            _ => None,
        };
        let format_into = |s: &mut File| {
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
            let count = unwind::on_unwind(&abandon, || emit(&mut Stream { file: s, index }));
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

/// _snprintf's body: _vsnprintf's work over the variadic call's arguments.
///
/// # Safety
///
/// As _vsnprintf's.
pub unsafe extern "C" fn snprintf_va(
    buffer: *mut u8,
    count: usize,
    text: *const u8,
    args: *const u8,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { vsnprintf(buffer, count, text, args) }
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

/// vswprintf: MSVC 6's, without a count: swprintf with its arguments as a `va_list`.
///
/// # Safety
///
/// As sprintf_va's, in wide units; `args` is the caller's `va_list`.
#[unsafe(export_name = "f2k_export_vswprintf")]
pub unsafe extern "C" fn vswprintf(buffer: *mut u16, text: *const u16, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { swprintf_va(buffer, text, args) }
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

    /// wprintf(format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export_wprintf")]
    pub unsafe extern "C" fn wprintf() {
        core::arch::naked_asm!(
            "lea eax, [esp+8]",
            "push eax",
            "push dword ptr [esp+8]",
            "call {body}",
            "add esp, 8",
            "ret",
            body = sym wprintf_va,
        )
    }

    /// fwprintf(stream, format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export_fwprintf")]
    pub unsafe extern "C" fn fwprintf() {
        core::arch::naked_asm!(
            "lea eax, [esp+12]",
            "push eax",
            "push dword ptr [esp+12]",
            "push dword ptr [esp+12]",
            "call {body}",
            "add esp, 12",
            "ret",
            body = sym fwprintf_va,
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

    /// _snprintf(buffer, count, format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export__snprintf")]
    pub unsafe extern "C" fn snprintf() {
        core::arch::naked_asm!(
            "lea eax, [esp+16]",
            "push eax",
            "push dword ptr [esp+16]",
            "push dword ptr [esp+16]",
            "push dword ptr [esp+16]",
            "call {body}",
            "add esp, 16",
            "ret",
            body = sym snprintf_va,
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
    // SAFETY: the caller's stream.
    unsafe { with_stream(stream, |s, _| close_file(s)) }
}

/// fclose's work, under the stream's lock.
fn close_file(s: &mut File) -> i32 {
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
        // SAFETY: a `FILE` the C runtime keeps: its temporary name is a block of the C runtime's
        // heap, forgotten below.
        unsafe { crate::heap::release(s.tmpfname) };
    }
    *s = File::UNUSED;
    result
}

/// `_iob`'s stream `index` closed, as fclose closes it.
pub fn close_at(index: usize) -> i32 {
    with_iob(index, |s, _| close_file(s))
}

/// A stream of `_iob`'s over descriptor `fd`, writing or reading as `writing` says (its
/// translation the descriptor's): its index, or none with EMFILE when none is free.
pub fn open_over(fd: i32, writing: bool) -> Option<usize> {
    claim(if writing { IOWRT } else { IOREAD }, fd)
}

/// `_iob`'s stream `index`, as programs are handed it.
pub fn stream(index: usize) -> *mut File {
    stream_at(index)
}

/// A stream's index in `_iob`; none for any other address (a program's own `FILE`, or none).
pub fn index(stream: *mut File) -> Option<usize> {
    index_of(stream)
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
    match claim(flag, fd) {
        Some(i) => stream_at(i),
        None => core::ptr::null_mut(),
    }
}

/// The first free stream of `_iob`'s claimed for descriptor `fd` with the `_flag` bits `flag`: its
/// index, or none with EMFILE. Each stream is looked at, and claimed when free, under its own lock.
fn claim(flag: i32, fd: i32) -> Option<usize> {
    let found = (0..IOB_ENTRIES).find(|&i| {
        with_iob(i, |s, _| {
            let free = s.flag & (IOREAD | IOWRT | IORW) == 0;
            if free {
                *s = File {
                    flag,
                    file: fd,
                    ..File::UNUSED
                };
            }
            free
        })
    });
    if found.is_none() {
        set_errno(EMFILE);
    }
    found
}

/// fopen's mode as `_open`'s flags and the stream's `_flag` bits, as MSDN's fopen documents it:
/// `r` reads an existing file, `w` writes a file it creates or truncates, `a` writes at the end of
/// one it creates when missing; `+` both reads and writes; `t` or `b` sets the translation (else
/// `_fmode` does). The other letters MSDN lists (`c`, `n`, and the hints) change nothing here.
/// None for a mode starting otherwise (EINVAL).
fn open_mode(mode: &[u8]) -> Option<(i32, i32)> {
    let (mut oflag, mut flag) = match mode.first() {
        Some(b'r') => (lowio::O_RDONLY, IOREAD),
        Some(b'w') => (lowio::O_WRONLY | lowio::O_CREAT | lowio::O_TRUNC, IOWRT),
        Some(b'a') => (lowio::O_WRONLY | lowio::O_CREAT | lowio::O_APPEND, IOWRT),
        _ => return None,
    };
    for &letter in &mode[1..] {
        match letter {
            b'+' => {
                oflag = (oflag & !(lowio::O_WRONLY | lowio::O_RDONLY)) | lowio::O_RDWR;
                flag = IORW;
            }
            b't' => oflag |= lowio::O_TEXT,
            b'b' => oflag |= lowio::O_BINARY,
            _ => {}
        }
    }
    Some((oflag, flag))
}

/// fopen: the file `name` opened as `mode` says ([`open_mode`]) through `_open` (shared for
/// reading and writing; a created file is read-write), and a stream over its descriptor. NULL for
/// a bad mode (EINVAL), no free stream (EMFILE: checked first, as MSVC's fopen takes the stream
/// before it opens the file), or `_open`'s failure (its errno).
///
/// # Safety
///
/// `name` and `mode` are NUL-terminated.
#[unsafe(export_name = "f2k_export_fopen")]
pub unsafe extern "C" fn fopen(name: *const u8, mode: *const u8) -> *mut File {
    // SAFETY: the caller's mode string.
    let mode = unsafe { bytes_until_nul(mode) };
    let Some((oflag, flag)) = open_mode(mode) else {
        set_errno(EINVAL);
        return core::ptr::null_mut();
    };
    // The stream first, held with no descriptor while the file opens.
    let Some(i) = claim(flag, -1) else {
        return core::ptr::null_mut();
    };
    // SAFETY: the caller's NUL-terminated name.
    let fd = unsafe { lowio::open_file(name, oflag, lowio::S_IREAD | lowio::S_IWRITE) };
    with_iob(i, |s, _| {
        if fd < 0 {
            *s = File::UNUSED;
        } else {
            s.file = fd;
        }
    });
    if fd < 0 {
        core::ptr::null_mut()
    } else {
        stream_at(i)
    }
}

/// fputs: the string written to the stream (stdout or stderr on a device through a buffer lent
/// for the call, as printf's output); 0, or EOF when a write failed.
///
/// # Safety
///
/// `text` is NUL-terminated; `stream` is a stream.
#[unsafe(export_name = "f2k_export_fputs")]
pub unsafe extern "C" fn fputs(text: *const u8, stream: *mut File) -> i32 {
    // SAFETY: the caller's string and stream.
    let written = unsafe {
        output(stream, |out| {
            for &byte in bytes_until_nul(text) {
                out.put(u32::from(byte));
            }
            0
        })
    };
    if written < 0 {
        EOF
    } else {
        0
    }
}

/// The bytes of `bytes` read from the stream's buffer (refilled from its descriptor as it empties):
/// the count, short at the end of the file or an error. A stream writing reads nothing (`_IOERR`,
/// as fill sets it).
fn read_bytes(s: &mut File, bytes: &mut [u8]) -> usize {
    let mut done = 0;
    while done < bytes.len() {
        if s.flag & (IOREAD | IOWRT) == IOREAD && s.cnt > 0 {
            // What the buffer holds, at once.
            let count = (s.cnt as usize).min(bytes.len() - done);
            // SAFETY: a `FILE` the C runtime keeps (see `with_stream`): reading, its `_cnt` bytes
            // at `_ptr` are the buffer's.
            let held = unsafe { core::slice::from_raw_parts(s.ptr, count) };
            bytes[done..done + count].copy_from_slice(held);
            // SAFETY: as above: `_ptr` moves within the bytes held.
            s.ptr = unsafe { s.ptr.add(count) };
            s.cnt -= count as i32;
            done += count;
            continue;
        }
        match fill(s) {
            EOF => break,
            c => {
                bytes[done] = c as u8;
                done += 1;
            }
        }
    }
    done
}

/// A byte written to the stream: through its buffer while it is writing, else as the buffer's
/// first (a stream reading cannot switch at once: `_IOERR`, as flush_and_put sets it).
fn write_byte(c: u8, s: &mut File, index: Option<usize>) -> i32 {
    if s.flag & IOWRT != 0 {
        put(c, s, index)
    } else {
        flush_and_put(c, s, index)
    }
}

/// The bytes of `count` items of `size` bytes: none for an empty request, or one past the address
/// space.
fn total(size: usize, count: usize) -> Option<usize> {
    size.checked_mul(count).filter(|&total| total > 0)
}

/// fread: up to `count` items of `size` bytes from the stream into `buffer`: the count of complete
/// items (short at the end of the file or an error, feof and ferror tell which); 0 for an empty
/// request, the stream untouched.
///
/// # Safety
///
/// `buffer` holds `size * count` bytes; `stream` is a stream.
#[unsafe(export_name = "f2k_export_fread")]
pub unsafe extern "C" fn fread(
    buffer: *mut u8,
    size: usize,
    count: usize,
    stream: *mut File,
) -> usize {
    let Some(total) = total(size, count) else {
        return 0;
    };
    // SAFETY: the caller's buffer of `total` bytes, the call's alone.
    let bytes = unsafe { core::slice::from_raw_parts_mut(buffer, total) };
    // SAFETY: the caller's stream.
    unsafe { with_stream(stream, |s, _| read_bytes(s, bytes)) / size }
}

/// fwrite: `count` items of `size` bytes from `buffer` to the stream (stdout or stderr on a device
/// through a buffer lent for the call, as fputs writes): the count of items written whole; 0 for an
/// empty request.
///
/// # Safety
///
/// `buffer` holds `size * count` bytes; `stream` is a stream.
#[unsafe(export_name = "f2k_export_fwrite")]
pub unsafe extern "C" fn fwrite(
    buffer: *const u8,
    size: usize,
    count: usize,
    stream: *mut File,
) -> usize {
    let Some(total) = total(size, count) else {
        return 0;
    };
    // SAFETY: the caller's buffer of `total` bytes, unchanged during the call.
    let bytes = unsafe { core::slice::from_raw_parts(buffer, total) };
    let mut written = 0;
    // SAFETY: the caller's stream.
    unsafe {
        output(stream, |out| {
            for &byte in bytes.iter() {
                if write_byte(byte, out.file, out.index) == EOF {
                    break;
                }
                written += 1;
            }
            0
        })
    };
    written / size
}

/// The stream's position as ftell answers it ([`file_position`] over its descriptor's); -1 (errno)
/// when the descriptor has no position.
fn position(s: &mut File) -> i32 {
    if s.cnt < 0 {
        s.cnt = 0;
    }
    let at = lowio::position(s.file);
    if at < 0 {
        return -1;
    }
    file_position(s, at, lowio::is_text(s.file))
}

/// The stream's position in its file's bytes, its descriptor's being `at`: less the bytes buffered
/// for reading, or plus the bytes pending to be written, each LF among them counted as the CR LF
/// it is in the file when `text`.
fn file_position(s: &File, at: i32, text: bool) -> i32 {
    let file_bytes = |bytes: &[u8]| {
        let lines = if text {
            bytes.iter().filter(|&&byte| byte == b'\n').count()
        } else {
            0
        };
        (bytes.len() + lines) as i32
    };
    if s.flag & IOREAD != 0 && s.cnt > 0 {
        // SAFETY: a `FILE` the C runtime keeps (see `with_stream`): reading, its `_cnt` bytes at
        // `_ptr` are the buffer's.
        let held = unsafe { core::slice::from_raw_parts(s.ptr, s.cnt as usize) };
        return at - file_bytes(held);
    }
    if s.flag & IOWRT != 0 && s.flag & (IOMYBUF | IOYOURBUF) != 0 {
        return at + file_bytes(pending(s).1);
    }
    at
}

/// ftell: the stream's position, as a count of the file's bytes ([`position`]); -1 (errno) on an
/// error.
///
/// # Safety
///
/// `stream` is a stream.
#[unsafe(export_name = "f2k_export_ftell")]
pub unsafe extern "C" fn ftell(stream: *mut File) -> i32 {
    // SAFETY: the caller's stream.
    unsafe { with_stream(stream, |s, _| position(s)) }
}

/// fseek's origins (stdio.h's SEEK_SET, SEEK_CUR and SEEK_END).
const SEEK_SET: u32 = 0;
const SEEK_CUR: u32 = 1;
const SEEK_END: u32 = 2;

/// fseek: the stream moved to `offset` from `origin` (the start, the current position, the end):
/// its pending output written, its buffered input dropped, its end of the file cleared (the
/// descriptor's Ctrl-Z too), and a stream opened for update free to read or write next. 0, or -1:
/// EINVAL for another origin, the descriptor's error for a position it refuses.
///
/// # Safety
///
/// `stream` is a stream.
#[unsafe(export_name = "f2k_export_fseek")]
pub unsafe extern "C" fn fseek(stream: *mut File, offset: i32, origin: i32) -> i32 {
    let origin = origin as u32;
    if !matches!(origin, SEEK_SET | SEEK_CUR | SEEK_END) {
        set_errno(EINVAL);
        return -1;
    }
    let body = |s: &mut File, _| {
        s.flag &= !IOEOF;
        let (offset, origin) = if origin == SEEK_CUR {
            let at = position(s);
            if at < 0 {
                return -1;
            }
            (at.wrapping_add(offset), SEEK_SET)
        } else {
            (offset, origin)
        };
        if flush(s) == EOF {
            return -1;
        }
        if s.flag & IORW != 0 {
            s.flag &= !(IOREAD | IOWRT);
        }
        if lowio::seek(s.file, offset, origin) < 0 {
            -1
        } else {
            0
        }
    };
    // SAFETY: the caller's stream.
    unsafe { with_stream(stream, body) }
}

/// clearerr: the stream's end-of-file and error indicators cleared.
///
/// # Safety
///
/// `stream` is a stream.
#[unsafe(export_name = "f2k_export_clearerr")]
pub unsafe extern "C" fn clearerr(stream: *mut File) {
    // SAFETY: the caller's stream.
    unsafe { with_stream(stream, |s, _| s.flag &= !(IOEOF | IOERR)) }
}

/// fputws: the wide string written to the stream as wprintf writes each character
/// ([`WideStream`]): in text mode in the LC_CTYPE locale's code page, in binary mode as its two
/// bytes. 0, or -1 (EOF, not the WEOF MSDN names: Windows 2000's capture answers -1): errno EILSEQ
/// for a character the code page lacks (the ones before it written), or a write that failed.
///
/// # Safety
///
/// `text` is NUL-terminated; `stream` is a stream.
#[unsafe(export_name = "f2k_export_fputws")]
pub unsafe extern "C" fn fputws(text: *const u16, stream: *mut File) -> i32 {
    // SAFETY: the caller's string.
    let units = unsafe { edge::wide(text) };
    let mut unconverted = false;
    // SAFETY: the caller's stream.
    let written = unsafe {
        output(stream, |out| {
            let text_mode = lowio::is_text(out.file.file);
            let mut wide = WideStream {
                stream: out,
                text: text_mode,
                unconverted: false,
            };
            for &unit in units {
                wide.put(u32::from(unit.get()));
                if wide.unconverted {
                    break;
                }
            }
            unconverted = wide.unconverted;
            0
        })
    };
    if unconverted {
        set_errno(EILSEQ);
        return -1;
    }
    if written < 0 {
        -1
    } else {
        0
    }
}

/// A wide character read from the stream: in text mode a byte, as mbtowc reads it in the LC_CTYPE
/// locale's code page; in binary mode two bytes, low first. None at the end (a lone last byte in
/// binary mode is no character) or on an error.
fn get_wide(s: &mut File, text: bool) -> Option<u16> {
    let low = get(s);
    if low == EOF {
        return None;
    }
    if text {
        return Some(ctype::byte_to_wide(low as u8));
    }
    let high = get(s);
    if high == EOF {
        return None;
    }
    Some(u16::from_le_bytes([low as u8, high as u8]))
}

/// fgetws: a line of wide characters (its newline kept), at most `n - 1` of them, NUL-terminated
/// into `buffer` ([`get_wide`] reads each); NULL at the end before any character, or on an error.
///
/// # Safety
///
/// `buffer` holds `n` wide characters; `stream` is a stream.
#[unsafe(export_name = "f2k_export_fgetws")]
pub unsafe extern "C" fn fgetws(buffer: *mut u16, n: i32, stream: *mut File) -> *mut u16 {
    if n <= 0 || stream.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller's buffer of `n` wide characters.
    let out = unsafe { edge::wide_parts_mut(buffer, n as usize) };
    let body = |s: &mut File, _| {
        let text = lowio::is_text(s.file);
        let mut length = 0usize;
        while length + 1 < out.len() {
            let Some(c) = get_wide(s, text) else {
                if length == 0 {
                    return false;
                }
                break;
            };
            out[length] = WideUnit::new(c);
            length += 1;
            if c == u16::from(b'\n') {
                break;
            }
        }
        out[length] = WideUnit::new(0);
        true
    };
    // SAFETY: the caller's stream.
    if unsafe { with_stream(stream, body) } {
        buffer
    } else {
        core::ptr::null_mut()
    }
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

    /// _snprintf's body is _vsnprintf over the variadic call's arguments (laid out as the host's: a
    /// pointer takes its own width): the count and a NUL when there is room for it, the count and
    /// no NUL for an exact fit, -1 and the buffer filled without a NUL when the text overflows.
    #[test]
    fn snprintf_bounds_as_vsnprintf_does() {
        let ab = b"ab\0";
        let mut list = Vec::new();
        list.extend(42u32.to_ne_bytes());
        list.extend((ab.as_ptr() as usize).to_ne_bytes());
        for (count, answer, expected) in [
            (8, 5, &b"42|ab\0##"[..]),
            (5, 5, b"42|ab###"),
            (3, -1, b"42|#####"),
            (0, -1, b"########"),
        ] {
            let mut out = [b'#'; 8];
            // SAFETY: a buffer of 8 bytes, `count` of them offered; the list holds what the
            // format consumes.
            let n =
                unsafe { snprintf_va(out.as_mut_ptr(), count, b"%d|%s\0".as_ptr(), list.as_ptr()) };
            assert_eq!((n, &out[..]), (answer, expected), "count {count}");
        }
    }

    /// strings' wformat block: vswprintf is swprintf over a `va_list` (laid out as the host's: a
    /// pointer takes its own width).
    #[test]
    fn vswprintf_takes_a_va_list() {
        use crate::format::tests::wide;
        let ab = wide("ab");
        let mut list = Vec::new();
        list.extend((-7i32).to_ne_bytes());
        list.extend(42u32.to_ne_bytes());
        list.extend(255u32.to_ne_bytes());
        list.extend((ab.as_ptr() as usize).to_ne_bytes());
        list.extend(('z' as u32).to_ne_bytes());
        let format = wide("%d|%u|%x|%5s|%-3c|%%");
        let mut out = [b'#' as u16; 32];
        // SAFETY: a buffer of 32 units; the list holds what the format consumes.
        let n = unsafe { vswprintf(out.as_mut_ptr(), format.as_ptr(), list.as_ptr()) };
        assert_eq!(n, 20);
        assert_eq!(
            String::from_utf16_lossy(&out[..22]),
            "-7|42|ff|   ab|z  |%\0#"
        );
        // SAFETY: as above, an empty format and no arguments.
        let n = unsafe { vswprintf(out.as_mut_ptr(), wide("").as_ptr(), list.as_ptr()) };
        assert_eq!((n, out[0]), (0, 0));
    }

    /// strings' wformat block's files: in text mode each wide character as the C locale's code
    /// page has it (below U+0100), one without a byte ending the output; in binary mode each
    /// character's two bytes, low first.
    #[test]
    fn wide_output_takes_the_descriptors_mode() {
        use crate::format::tests::{units_of, wide, List};
        let _locale = ctype::tests::LOCALE.lock().unwrap();
        // SAFETY: setlocale over a NUL-terminated name.
        unsafe { ctype::setlocale(0, b"C\0".as_ptr()) };
        let run = |text: bool, format: &str| {
            let mut buffer = [0u8; 64];
            let mut file = File {
                base: buffer.as_mut_ptr(),
                ptr: buffer.as_mut_ptr(),
                cnt: 64,
                bufsiz: 64,
                flag: IOWRT | IOYOURBUF,
                file: 2000,
                ..File::UNUSED
            };
            let mut stream = Stream {
                file: &mut file,
                index: None,
            };
            let mut out = WideStream {
                stream: &mut stream,
                text,
                unconverted: false,
            };
            let count = format::format(
                &units_of(&wide(format)),
                &mut List(Default::default()),
                &mut out,
            );
            let unconverted = out.unconverted;
            let written = 64 - file.cnt as usize;
            (count, unconverted, buffer[..written].to_vec())
        };
        assert_eq!(run(true, "a\nb\n"), (4, false, b"a\nb\n".to_vec()));
        assert_eq!(run(false, "a\nb\n"), (4, false, b"a\0\n\0b\0\n\0".to_vec()));
        assert_eq!(run(true, "[é]\n"), (4, false, b"[\xE9]\n".to_vec()));
        assert_eq!(
            run(false, "[é]\n"),
            (4, false, b"[\0\xE9\0]\0\n\0".to_vec())
        );
        assert_eq!(run(true, "[α]\n"), (4, true, b"[".to_vec()));
        assert_eq!(
            run(false, "[α]\n"),
            (4, false, b"[\0\xB1\x03]\0\n\0".to_vec())
        );
    }

    /// A stream reading over `buffer` as a fill left it: every byte buffered, none taken yet. Its
    /// descriptor is not open, so a refill fails (`_IOERR`).
    fn reading(buffer: &mut [u8]) -> File {
        File {
            base: buffer.as_mut_ptr(),
            ptr: buffer.as_mut_ptr(),
            cnt: buffer.len() as i32,
            bufsiz: buffer.len() as i32,
            flag: IOREAD | IOYOURBUF,
            file: 2000,
            ..File::UNUSED
        }
    }

    /// A stream writing into `buffer`, nothing pending.
    fn writing(buffer: &mut [u8]) -> File {
        File {
            base: buffer.as_mut_ptr(),
            ptr: buffer.as_mut_ptr(),
            cnt: buffer.len() as i32,
            bufsiz: buffer.len() as i32,
            flag: IOWRT | IOYOURBUF,
            file: 2000,
            ..File::UNUSED
        }
    }

    /// fd's streams block, its text-mode reads: "ab\r\ncd\r\nef" is buffered as "ab\ncd\nef" (the
    /// descriptor 10 bytes in); fread takes what the buffer holds, its complete items counted, and
    /// ftell counts each LF still buffered as its CR LF. In binary mode the buffer is the file's.
    #[test]
    fn fread_and_ftell_count_the_files_bytes() {
        let mut text = *b"ab\ncd\nef";
        let mut file = reading(&mut text);
        let stream = core::ptr::addr_of_mut!(file);
        let mut out = [0u8; 16];
        // SAFETY: the test's stream and buffers.
        unsafe {
            assert_eq!(file_position(&*stream, 10, true), 0);
            assert_eq!(fread(out.as_mut_ptr(), 1, 4, stream), 4);
            assert_eq!(&out[..4], b"ab\nc");
            assert_eq!(file_position(&*stream, 10, true), 5);
            assert_eq!(fread(out.as_mut_ptr(), 3, 1, stream), 1);
            assert_eq!(&out[..3], b"d\ne");
            assert_eq!(file_position(&*stream, 10, true), 9);
            // "f", then the refill fails: no whole item.
            assert_eq!(fread(out.as_mut_ptr(), 3, 1, stream), 0);
            assert_eq!(out[0], b'f');
            assert_eq!((*stream).flag & IOERR, IOERR);
            assert_eq!(fread(out.as_mut_ptr(), 0, 5, stream), 0);
            assert_eq!(fread(out.as_mut_ptr(), 5, 0, stream), 0);
        }
        let mut binary = *b"ab\r\ncd\r\nef";
        let mut file = reading(&mut binary);
        let stream = core::ptr::addr_of_mut!(file);
        // SAFETY: as above.
        unsafe {
            assert_eq!(fread(out.as_mut_ptr(), 2, 2, stream), 2);
            assert_eq!(&out[..4], b"ab\r\n");
            assert_eq!(file_position(&*stream, 10, false), 4);
        }
    }

    /// fd's streams block, its text-mode writes: fwrite buffers the caller's bytes, its complete
    /// items counted, and ftell counts each LF pending as the CR LF it goes out as; a stream
    /// opened for reading takes none (`_IOERR`), and clearerr clears its indicators.
    #[test]
    fn fwrite_and_ftell_count_the_files_bytes() {
        let mut buffer = [0u8; 64];
        let mut file = writing(&mut buffer);
        let stream = core::ptr::addr_of_mut!(file);
        // SAFETY: the test's stream and buffers.
        unsafe {
            assert_eq!(file_position(&*stream, 0, true), 0);
            assert_eq!(fwrite(b"ab\ncd\n".as_ptr(), 1, 6, stream), 6);
            assert_eq!(file_position(&*stream, 0, true), 8);
            assert_eq!(fwrite(b"xy\nz".as_ptr(), 2, 2, stream), 2);
            assert_eq!(file_position(&*stream, 0, true), 13);
            assert_eq!(file_position(&*stream, 0, false), 10);
            assert_eq!(fwrite(b"q".as_ptr(), 1, 0, stream), 0);
            assert_eq!(fwrite(b"q".as_ptr(), 0, 1, stream), 0);
            assert_eq!(pending(&*stream).1, b"ab\ncd\nxy\nz");
        }
        let mut text = *b"ab";
        let mut file = File {
            flag: IOREAD,
            ..reading(&mut text)
        };
        let stream = core::ptr::addr_of_mut!(file);
        // SAFETY: as above.
        unsafe {
            assert_eq!(fwrite(b"x".as_ptr(), 1, 1, stream), 0);
            assert_eq!((*stream).flag & IOERR, IOERR);
            (*stream).flag |= IOEOF;
            clearerr(stream);
            assert_eq!((*stream).flag & (IOERR | IOEOF), 0);
        }
    }

    /// fseek refuses an origin other than SEEK_SET, SEEK_CUR and SEEK_END (EINVAL), the stream
    /// untouched; one whose descriptor has no position fails.
    #[test]
    fn fseek_checks_its_origin() {
        let mut text = *b"abc";
        let mut file = File {
            flag: IOREAD | IOYOURBUF | IOEOF,
            ..reading(&mut text)
        };
        let stream = core::ptr::addr_of_mut!(file);
        // SAFETY: the test's stream.
        unsafe {
            set_errno(0);
            assert_eq!(fseek(stream, 0, 7), -1);
            assert_eq!(crate::thread::errno(), EINVAL);
            assert_eq!(((*stream).cnt, (*stream).flag & IOEOF), (3, IOEOF));
            assert_eq!(fseek(stream, 1, SEEK_CUR as i32), -1);
            assert_eq!((*stream).flag & IOEOF, 0);
        }
    }

    /// fgetws's characters: in text mode one byte each, as mbtowc reads it in the "C" locale; in
    /// binary mode two bytes each, low first, a lone last byte no character.
    #[test]
    fn wide_characters_are_read_as_the_mode_says() {
        let _locale = ctype::tests::LOCALE.lock().unwrap();
        // SAFETY: setlocale over a NUL-terminated name.
        unsafe { ctype::setlocale(0, b"C\0".as_ptr()) };
        let mut text = *b"a\xE9\n";
        let mut file = reading(&mut text);
        let read: Vec<u16> = (0..3).filter_map(|_| get_wide(&mut file, true)).collect();
        assert_eq!(read, [0x61, 0xE9, 0x0A]);
        let mut binary = *b"a\0\xB1\x03b";
        let mut file = reading(&mut binary);
        assert_eq!(get_wide(&mut file, false), Some(0x61));
        assert_eq!(get_wide(&mut file, false), Some(0x3B1));
        assert_eq!(get_wide(&mut file, false), None);
    }
}
