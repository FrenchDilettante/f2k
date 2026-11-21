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
//! - ungetc pushes a character back into the buffer, before `_ptr` ([`unget`], VC6's): one at
//!   least, even on a stream that has read nothing yet, and as many as it has read from its buffer;
//!   it clears the end of the file. ungetwc pushes a wide character back as fgetws reads it: a byte
//!   in text mode, two in binary mode.
//! - fclose flushes, frees the stream's own buffer and closes its descriptor.
//! - fread and fwrite move bytes through the buffer, as getc and putc do, and answer the items
//!   moved whole. ftell counts the file's bytes as VC6's reckons them ([`file_position`]): in text
//!   mode each LF pending counts as the CR LF it goes out as, and a read's position is the fill's
//!   bytes counted back from the file's end, each LF as CR LF, which a file of bare LFs reads back
//!   short (MSDN's ftell: only fseek need take the value back). fseek writes what is pending, drops
//!   what is buffered, clears the end of the file (the descriptor's Ctrl-Z too), and leaves a `+`
//!   stream free to read or write next (a stream reading alone refills with 512 bytes first);
//!   clearerr clears the end-of-file and error indicators alone.
//! - A program has up to 512 streams open at once, as VC6's `_NSTREAM_`: `_iob`'s 20, then streams
//!   of the C runtime's heap made as the ones before them are all taken ([`claim`]). fflush(NULL)
//!   flushes those writing; `_flushall` flushes every one in use and counts them; `_fcloseall`
//!   closes all but stdin, stdout and stderr and frees the heap's.
//! - `_popen`'s streams ([`crate::process`]) are streams over a pipe's end like any other.
//! - fscanf and scanf scan a stream's bytes, fwscanf and wscanf its wide characters as fgetws reads
//!   them ([`crate::scan`]): the character the scan reads ahead and does not take is pushed back,
//!   as ungetc pushes it, for the next read.
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

use core::sync::atomic::{AtomicPtr, Ordering};

use rtl::cstr::bytes_until_nul;
use rtl::sync::Locked;

use crate::ctype;
use crate::data::{File, IOB, IOB_ENTRIES, STREAMS, STREAM_BUFFER};
use crate::edge::{self, WideUnit};
use crate::format::{self, Args, Output, Unbounded, Unit, VaList};
use crate::lowio;
use crate::scan::{self, Units};
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
/// The stream's last fill stopped at a text file's Ctrl-Z (VC6's `_IOCTRLZ`): ftell counts it.
const IOCTRLZ: i32 = 0x2000;
/// The buffer bits: a stream with none of them has no buffer yet.
const BUFFERED: i32 = IOMYBUF | IONBF | IOYOURBUF;

/// setvbuf's modes (`_IOLBF` is `_IOFBF` on Win32, MSDN says).
const IOFBF: i32 = 0x0000;
const IOLBF: i32 = 0x0040;

/// EOF.
const EOF: i32 = -1;

/// The buffer a stream reading alone refills with first after fseek (VC6's `_SMALL_BUFSIZ`), so
/// that a seek's next read costs less; the fill after it takes the whole buffer again.
const SMALL_BUFFER: i32 = 512;

/// Each stream's lock (Windows 2000's per-stream lock, a critical section), by its index: the C
/// runtime changes the stream's `FILE` only under it ([`with_stream`]). A bare [`Lock`], taken
/// through [`Lock::holding`] (let go when an exception unwinds out of the call), not a `Locked`
/// value: its holder may take it again, as Windows 2000's critical section lets it.
static LOCKS: [Lock; STREAMS] = [const { Lock::new() }; STREAMS];

/// The lock of a stream that is not one of the C runtime's (a program's own `FILE`).
static OTHER: Lock = Lock::new();

/// The lock held while the streams are looked through for a free one, or flushed or closed all
/// at once (VC6's `_IOB_SCAN_LOCK`): the streams past `_iob`'s are made and freed only under it.
/// Taken before any stream's own lock.
static SCAN: Lock = Lock::new();

/// The streams past `_iob`'s, by index (VC6's `__piob` past its first 20): each a `FILE` of the C
/// runtime's heap, made when every stream before it is taken (null until then), freed by
/// `_fcloseall`.
static EXTRA: [AtomicPtr<File>; STREAMS - IOB_ENTRIES] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; STREAMS - IOB_ENTRIES];

/// The buffers lent to stdout and stderr for a call, each taken under its stream's lock.
static LENT: [Locked<[u8; STREAM_BUFFER], UnwindLock>; 2] =
    [const { Locked::new(UnwindLock::new(), [0; STREAM_BUFFER]) }; 2];

/// The stream at `index`: `_iob`'s, or one of the heap's (null when it is not made).
fn stream_at(index: usize) -> *mut File {
    match index.checked_sub(IOB_ENTRIES) {
        None => IOB.get().cast::<File>().wrapping_add(index),
        Some(extra) => EXTRA[extra].load(Ordering::Acquire),
    }
}

/// A stream's index among the C runtime's, when it is one of them.
fn index_of(stream: *mut File) -> Option<usize> {
    let offset = (stream as usize).wrapping_sub(stream_at(0) as usize);
    let size = core::mem::size_of::<File>();
    if offset.is_multiple_of(size) && offset / size < IOB_ENTRIES {
        return Some(offset / size);
    }
    if stream.is_null() {
        return None;
    }
    EXTRA
        .iter()
        .position(|extra| extra.load(Ordering::Acquire) == stream)
        .map(|extra| IOB_ENTRIES + extra)
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

/// [`with_stream`] over the C runtime's stream `index`, which is made.
fn with_iob<R>(index: usize, body: impl FnOnce(&mut File, Option<usize>) -> R) -> R {
    // SAFETY: one of `_iob`'s streams, the DLL's own for the process's life, or one of the heap's,
    // made (the callers': under the scan lock, or one they claimed), freed only by `_fcloseall`.
    unsafe { with_stream(stream_at(index), body) }
}

/// Whether a stream is in use: open for reading, writing or both.
fn in_use(s: &File) -> bool {
    s.flag & (IOREAD | IOWRT | IORW) != 0
}

/// `body` run over each of the C runtime's streams that is made and in use, in index order,
/// under the scan lock and each stream's own lock in turn.
fn each_in_use(mut body: impl FnMut(&mut File)) {
    SCAN.holding(|| {
        for index in 0..STREAMS {
            if stream_at(index).is_null() {
                continue;
            }
            with_iob(index, |s, _| {
                if in_use(s) {
                    body(s);
                }
            });
        }
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
    if s.flag & (IOWRT | IORW) == 0 && lowio::stopped_at_ctrl_z(s.file) {
        s.flag |= IOCTRLZ;
    }
    if s.bufsiz == SMALL_BUFFER && own_buffer(s) {
        s.bufsiz = STREAM_BUFFER as i32;
    }
    s.cnt = count - 1;
    // Inside the bytes read.
    take(s) as i32
}

/// Whether the stream's buffer is the C runtime's own, of its size: neither a caller's nor one
/// setvbuf sized.
fn own_buffer(s: &File) -> bool {
    s.flag & (IOMYBUF | IOSETVBUF) == IOMYBUF
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
    each_in_use(|s| {
        if s.flag & (IOWRT | IORW) != 0 && s.flag & IOREAD == 0 && flush(s) == EOF {
            result = EOF;
        }
    });
    result
}

/// _flushall: every stream in use flushed (a reading one's buffered input dropped, as fflush
/// drops it): the count of those flushed without an error. fd's nfiles capture: 43 for 40 files
/// and the three standard streams.
#[unsafe(export_name = "f2k_export__flushall")]
pub extern "C" fn flushall() -> i32 {
    let mut count = 0;
    each_in_use(|s| {
        if flush(s) != EOF {
            count += 1;
        }
    });
    count
}

/// _fcloseall: every stream in use but stdin, stdout and stderr closed, as fclose closes it, and
/// the streams of the heap freed: the count closed without an error (fd's nfiles capture: 40,
/// then 0).
#[unsafe(export_name = "f2k_export__fcloseall")]
pub extern "C" fn fcloseall() -> i32 {
    let mut count = 0;
    SCAN.holding(|| {
        for index in 3..STREAMS {
            let stream = stream_at(index);
            if stream.is_null() {
                continue;
            }
            let closed = with_iob(index, |s, _| in_use(s) && close_file(s) != EOF);
            if closed {
                count += 1;
            }
            if let Some(extra) = index.checked_sub(IOB_ENTRIES) {
                EXTRA[extra].store(core::ptr::null_mut(), Ordering::Release);
                // SAFETY: a stream of the C runtime's heap, made by `claim`, no longer reachable
                // through the table; a program still holding it holds a stream that is closed.
                unsafe { crate::heap::release(stream.cast()) };
            }
        }
    });
    count
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

/// The caller's buffer of `count` units, as the bounded formatters write it. VC6's _vsnprintf
/// keeps the count in its string stream's `_cnt`, an int, so a count past INT_MAX (`(size_t)-1`
/// among them) is a negative room: no room, every unit refused, nothing written and -1 for any
/// text. A count past what the address space holds in units is the most it holds (no buffer is
/// larger).
///
/// # Safety
///
/// `buffer` holds `count` units (of any alignment), the call's alone, when the count is an int's.
unsafe fn units_out<'a, U>(buffer: *mut U, count: usize) -> &'a mut [U] {
    let room = if count > i32::MAX as usize {
        0
    } else {
        count.min(isize::MAX as usize / core::mem::size_of::<U>().max(1))
    };
    if room == 0 {
        return &mut [];
    }
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts_mut(buffer, room) }
}

/// _vsnprintf: at most `count` bytes into `buffer` (see [`format::bounded`]), the count read as
/// an int ([`units_out`]).
///
/// # Safety
///
/// `buffer` holds `count` bytes (none past INT_MAX); `text` is NUL-terminated; `args` is the
/// caller's `va_list`.
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

/// vsprintf: sprintf with its arguments as a `va_list`.
///
/// # Safety
///
/// As sprintf_va's; `args` is the caller's `va_list`.
#[unsafe(export_name = "f2k_export_vsprintf")]
pub unsafe extern "C" fn vsprintf(buffer: *mut u8, text: *const u8, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { sprintf_va(buffer, text, args) }
}

/// vprintf: printf with its arguments as a `va_list`.
///
/// # Safety
///
/// As printf_va's; `args` is the caller's `va_list`.
#[unsafe(export_name = "f2k_export_vprintf")]
pub unsafe extern "C" fn vprintf(text: *const u8, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { printf_va(text, args) }
}

/// vfprintf: fprintf with its arguments as a `va_list`.
///
/// # Safety
///
/// As fprintf_va's; `args` is the caller's `va_list`.
#[unsafe(export_name = "f2k_export_vfprintf")]
pub unsafe extern "C" fn vfprintf(stream: *mut File, text: *const u8, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { fprintf_va(stream, text, args) }
}

/// vwprintf: wprintf with its arguments as a `va_list`.
///
/// # Safety
///
/// As wprintf_va's; `args` is the caller's `va_list`.
#[unsafe(export_name = "f2k_export_vwprintf")]
pub unsafe extern "C" fn vwprintf(text: *const u16, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { wprintf_va(text, args) }
}

/// vfwprintf: fwprintf with its arguments as a `va_list`.
///
/// # Safety
///
/// As fwprintf_va's; `args` is the caller's `va_list`.
#[unsafe(export_name = "f2k_export_vfwprintf")]
pub unsafe extern "C" fn vfwprintf(stream: *mut File, text: *const u16, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { fwprintf_va(stream, text, args) }
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

/// swscanf's body: the wide string scanned ([`scan::scan`]).
///
/// # Safety
///
/// `input` and `text` are NUL-terminated; `args` holds the pointers its fields store through.
pub unsafe extern "C" fn swscanf_va(input: *const u16, text: *const u16, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe {
        scan::scan(
            &mut Units::new(edge::wide(input)),
            edge::wide(text),
            &mut VaList::new(args),
        )
    }
}

/// sscanf's body: the narrow string scanned ([`scan::scan`]).
///
/// # Safety
///
/// As swscanf_va's, in bytes.
pub unsafe extern "C" fn sscanf_va(input: *const u8, text: *const u8, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe {
        scan::scan(
            &mut Units::new(bytes_until_nul(input)),
            bytes_until_nul(text),
            &mut VaList::new(args),
        )
    }
}

/// A stream a scan reads (fscanf's and fwscanf's), under its lock: its bytes (`wide` none), or its
/// wide characters as [`get_wide`] reads them in the descriptor's mode (`wide` whether it is text).
/// The character read ahead and not taken goes back into the stream when the scan ends
/// ([`StreamInput::finish`]), as VC6's input.c ungets it: the next read starts there.
struct StreamInput<'a> {
    file: &'a mut File,
    wide: Option<bool>,
    /// The character read ahead, none at the end; none read yet.
    ahead: Option<Option<u16>>,
}

impl scan::Source for StreamInput<'_> {
    fn peek(&mut self) -> Option<u16> {
        if self.ahead.is_none() {
            let unit = match self.wide {
                None => match get(self.file) {
                    EOF => None,
                    c => Some(c as u16),
                },
                Some(text) => get_wide(self.file, text),
            };
            self.ahead = Some(unit);
        }
        self.ahead.flatten()
    }

    fn take(&mut self) {
        self.ahead = None;
    }
}

impl StreamInput<'_> {
    /// The scan's end: the character read ahead and not taken pushed back ([`unget`]).
    fn finish(self) {
        if let Some(Some(unit)) = self.ahead {
            match self.wide {
                None => unget(&[unit as u8], self.file),
                Some(text) => unget_wide(unit, self.file, text),
            };
        }
    }
}

/// The stream scanned against the format ([`scan::scan`], a format of `U`'s width reading the
/// stream's characters of that width), under its lock; EOF for a null stream.
///
/// # Safety
///
/// `stream` is null or a stream; `args` holds the pointers the format's fields store through.
unsafe fn scan_stream<U: Unit>(stream: *mut File, format: &[U], args: &mut impl Args) -> i32 {
    if stream.is_null() {
        return EOF;
    }
    let body = |s: &mut File, _| {
        let wide = U::WIDE.then(|| s.flag & IOSTRG == 0 && lowio::is_text(s.file));
        let mut input = StreamInput {
            file: s,
            wide,
            ahead: None,
        };
        let count = scan::scan(&mut input, format, args);
        input.finish();
        count
    };
    // SAFETY: the caller's stream.
    unsafe { with_stream(stream, body) }
}

/// fscanf's body: the stream's bytes scanned.
///
/// # Safety
///
/// `stream` is null or a stream; `text` is NUL-terminated; `args` holds the pointers its fields
/// store through.
pub unsafe extern "C" fn fscanf_va(stream: *mut File, text: *const u8, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { scan_stream(stream, bytes_until_nul(text), &mut VaList::new(args)) }
}

/// scanf's body: stdin's bytes scanned.
///
/// # Safety
///
/// As fscanf_va's.
pub unsafe extern "C" fn scanf_va(text: *const u8, args: *const u8) -> i32 {
    // SAFETY: the caller's contract; stdin is `_iob[0]`.
    unsafe { fscanf_va(stream_at(0), text, args) }
}

/// fwscanf's body: the stream's wide characters scanned.
///
/// # Safety
///
/// As fscanf_va's, the format wide.
pub unsafe extern "C" fn fwscanf_va(stream: *mut File, text: *const u16, args: *const u8) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { scan_stream(stream, edge::wide(text), &mut VaList::new(args)) }
}

/// wscanf's body: stdin's wide characters scanned.
///
/// # Safety
///
/// As fwscanf_va's.
pub unsafe extern "C" fn wscanf_va(text: *const u16, args: *const u8) -> i32 {
    // SAFETY: the caller's contract; stdin is `_iob[0]`.
    unsafe { fwscanf_va(stream_at(0), text, args) }
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

    /// sscanf(input, format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export_sscanf")]
    pub unsafe extern "C" fn sscanf() {
        core::arch::naked_asm!(
            "lea eax, [esp+12]",
            "push eax",
            "push dword ptr [esp+12]",
            "push dword ptr [esp+12]",
            "call {body}",
            "add esp, 12",
            "ret",
            body = sym sscanf_va,
        )
    }

    /// fscanf(stream, format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export_fscanf")]
    pub unsafe extern "C" fn fscanf() {
        core::arch::naked_asm!(
            "lea eax, [esp+12]",
            "push eax",
            "push dword ptr [esp+12]",
            "push dword ptr [esp+12]",
            "call {body}",
            "add esp, 12",
            "ret",
            body = sym fscanf_va,
        )
    }

    /// scanf(format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export_scanf")]
    pub unsafe extern "C" fn scanf() {
        core::arch::naked_asm!(
            "lea eax, [esp+8]",
            "push eax",
            "push dword ptr [esp+8]",
            "call {body}",
            "add esp, 8",
            "ret",
            body = sym scanf_va,
        )
    }

    /// fwscanf(stream, format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export_fwscanf")]
    pub unsafe extern "C" fn fwscanf() {
        core::arch::naked_asm!(
            "lea eax, [esp+12]",
            "push eax",
            "push dword ptr [esp+12]",
            "push dword ptr [esp+12]",
            "call {body}",
            "add esp, 12",
            "ret",
            body = sym fwscanf_va,
        )
    }

    /// wscanf(format, ...).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export_wscanf")]
    pub unsafe extern "C" fn wscanf() {
        core::arch::naked_asm!(
            "lea eax, [esp+8]",
            "push eax",
            "push dword ptr [esp+8]",
            "call {body}",
            "add esp, 8",
            "ret",
            body = sym wscanf_va,
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

/// The first free stream claimed for descriptor `fd` with the `_flag` bits `flag`, as VC6's
/// `_getstream` finds it: the first of the streams made that is not in use, or else the first not
/// made yet, made of the C runtime's heap (fd's nfiles capture: 40 files open at once). Its index,
/// or none with EMFILE when all 512 are in use (or the heap has no room for the next). Under the
/// scan lock; each stream is looked at, and claimed when free, under its own lock.
fn claim(flag: i32, fd: i32) -> Option<usize> {
    let claimed = File {
        flag,
        file: fd,
        ..File::UNUSED
    };
    let found = SCAN.holding(|| {
        (0..STREAMS).find_map(|index| {
            if stream_at(index).is_null() {
                let made =
                    crate::heap::allocate(core::mem::size_of::<File>(), false).cast::<File>();
                if made.is_null() {
                    return Some(None);
                }
                // SAFETY: a new block of the C runtime's heap, a `FILE`'s size, aligned for one;
                // no other thread reaches it until the table holds it.
                unsafe { made.write(claimed) };
                EXTRA[index - IOB_ENTRIES].store(made, Ordering::Release);
                return Some(Some(index));
            }
            with_iob(index, |s, _| {
                let free = !in_use(s);
                if free {
                    *s = claimed;
                }
                free.then_some(Some(index))
            })
        })
    });
    let found = found.flatten();
    if found.is_none() {
        set_errno(EMFILE);
    }
    found
}

/// fopen's mode as `_open`'s flags and the stream's `_flag` bits, as VC6's `_openfile` reads it:
/// `r` reads an existing file, `w` writes a file it creates or truncates, `a` writes at the end of
/// one it creates when missing; then up to one each of `+` (both reads and writes), `t` or `b`
/// (the translation, else `_fmode`'s), `c` or `n` (the commit mode, which F2K's streams do not
/// keep), `S` or `R` (`_O_SEQUENTIAL`, `_O_RANDOM`), `T` (`_O_SHORT_LIVED`) and `D`
/// (`_O_TEMPORARY`). The reading stops at a letter it does not know or one of a kind it already
/// took, the rest ignored (fd's modes capture: "rzb" and "rtb" read in text mode, "rbt" in
/// binary). None for a mode starting otherwise.
fn open_mode(mode: &[u8]) -> Option<(i32, i32)> {
    let (mut oflag, mut flag) = match mode.first() {
        Some(b'r') => (lowio::O_RDONLY, IOREAD),
        Some(b'w') => (lowio::O_WRONLY | lowio::O_CREAT | lowio::O_TRUNC, IOWRT),
        Some(b'a') => (lowio::O_WRONLY | lowio::O_CREAT | lowio::O_APPEND, IOWRT),
        _ => return None,
    };
    /// `given` added to `oflag` unless a flag of its `kind` is there already: whether it was.
    fn once(oflag: &mut i32, given: i32, kind: i32) -> bool {
        let free = *oflag & kind == 0;
        if free {
            *oflag |= given;
        }
        free
    }
    let (mut commit, mut scan) = (false, false);
    for &letter in &mode[1..] {
        let taken = match letter {
            b'+' => {
                let free = oflag & lowio::O_RDWR == 0;
                if free {
                    oflag = (oflag & !(lowio::O_WRONLY | lowio::O_RDONLY)) | lowio::O_RDWR;
                    flag = IORW;
                }
                free
            }
            b't' => once(&mut oflag, lowio::O_TEXT, lowio::O_TEXT | lowio::O_BINARY),
            b'b' => once(&mut oflag, lowio::O_BINARY, lowio::O_TEXT | lowio::O_BINARY),
            b'T' => once(&mut oflag, lowio::O_SHORT_LIVED, lowio::O_SHORT_LIVED),
            b'D' => once(&mut oflag, lowio::O_TEMPORARY, lowio::O_TEMPORARY),
            b'c' | b'n' => !core::mem::replace(&mut commit, true),
            b'S' | b'R' => {
                let free = !core::mem::replace(&mut scan, true);
                if free {
                    oflag |= if letter == b'S' {
                        lowio::O_SEQUENTIAL
                    } else {
                        lowio::O_RANDOM
                    };
                }
                free
            }
            _ => false,
        };
        if !taken {
            break;
        }
    }
    Some((oflag, flag))
}

/// fopen: the file `name` opened as `mode` says ([`open_mode`]) through `_open` (shared for
/// reading and writing; a created file is read-write), and a stream over its descriptor. NULL for
/// no free stream (EMFILE: checked first, as VC6's fopen takes the stream before it reads the
/// mode), a bad mode (errno untouched: fd's modes capture shows `"q"` and `""` leaving it 0), or
/// `_open`'s failure (its errno).
///
/// # Safety
///
/// `name` and `mode` are NUL-terminated.
#[unsafe(export_name = "f2k_export_fopen")]
pub unsafe extern "C" fn fopen(name: *const u8, mode: *const u8) -> *mut File {
    // The stream first, held with no descriptor while the file opens.
    let Some(i) = claim(IOREAD, -1) else {
        return core::ptr::null_mut();
    };
    // SAFETY: the caller's mode string.
    let mode = unsafe { bytes_until_nul(mode) };
    let fd = match open_mode(mode) {
        Some((oflag, flag)) => {
            // SAFETY: the caller's NUL-terminated name.
            let fd = unsafe { lowio::open_file(name, oflag, lowio::S_IREAD | lowio::S_IWRITE) };
            (fd >= 0).then_some((fd, flag))
        }
        None => None,
    };
    with_iob(i, |s, _| match fd {
        Some((fd, flag)) => {
            s.file = fd;
            s.flag = flag;
        }
        None => *s = File::UNUSED,
    });
    match fd {
        Some(_) => stream_at(i),
        None => core::ptr::null_mut(),
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

/// The stream's position as ftell answers it ([`file_position`] over its descriptor's): -1 (errno)
/// when the descriptor has no position, or the stream is not open.
fn position(s: &mut File) -> i32 {
    if s.cnt < 0 {
        s.cnt = 0;
    }
    let fd = s.file;
    let at = lowio::seek(fd, 0, SEEK_CUR);
    if at < 0 {
        return -1;
    }
    let text = lowio::is_text(fd);
    let at_end = || {
        let end = lowio::seek(fd, 0, SEEK_END);
        if end != at {
            lowio::seek(fd, at, SEEK_SET);
        }
        end == at
    };
    let after_cr = || lowio::read_after_cr(fd);
    match file_position(s, at, text, at_end, after_cr) {
        Some(position) => position,
        None => {
            set_errno(EINVAL);
            -1
        }
    }
}

/// The stream's position in its file's bytes, its descriptor's being `at`, as VC6's ftell
/// reckons it. Writing, the bytes pending are added, each LF counted as the CR LF it goes out as
/// in `text` mode. Reading, the bytes the last fill took from the file are taken off and those
/// read from the buffer added: in `text` mode, the fill's bytes are its buffer's size (512 after
/// fseek's small fill, one more when `after_cr` says its first LF's CR came before it) unless
/// `at_end` says the descriptor is at the file's end, when they are the bytes it buffered, each
/// LF as CR LF and a Ctrl-Z it stopped at counted — so a text file of bare LFs reads back short
/// (fd's textmode capture: `-2` after its first byte). None for a stream that is not open.
fn file_position(
    s: &File,
    at: i32,
    text: bool,
    at_end: impl FnOnce() -> bool,
    after_cr: impl FnOnce() -> bool,
) -> Option<i32> {
    if s.flag & (IOMYBUF | IOYOURBUF) == 0 {
        return Some(at - s.cnt);
    }
    let lines = |bytes: &[u8]| bytes.iter().filter(|&&byte| byte == b'\n').count() as i32;
    let (taken, before) = pending(s);
    let mut offset = taken.max(0);
    if s.flag & (IOWRT | IOREAD) != 0 {
        if text {
            offset += lines(before);
        }
    } else if s.flag & IORW == 0 {
        return None;
    }
    if at == 0 {
        return Some(offset);
    }
    let mut at = at;
    if s.flag & IOREAD != 0 {
        if s.cnt == 0 {
            offset = 0;
        } else {
            let mut filled = s.cnt + taken.max(0);
            if text {
                if at_end() {
                    // SAFETY: a `FILE` the C runtime keeps (see `with_stream`): reading, its
                    // buffer holds the `_cnt` bytes after `_ptr`, and those before it.
                    let held = unsafe { core::slice::from_raw_parts(s.base, filled as usize) };
                    filled += lines(held);
                    if s.flag & IOCTRLZ != 0 {
                        filled += 1;
                    }
                } else {
                    filled = if filled <= SMALL_BUFFER && own_buffer(s) {
                        SMALL_BUFFER
                    } else {
                        s.bufsiz
                    };
                    if after_cr() {
                        filled += 1;
                    }
                }
            }
            at -= filled;
        }
    }
    Some(at + offset)
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
        } else if s.flag & IOREAD != 0 && own_buffer(s) {
            s.bufsiz = SMALL_BUFFER;
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

/// `bytes` pushed back into the stream, the first of them the next byte read (VC6's
/// `_ungetc_lk`, and `_ungetwc_lk`'s two bytes): only a stream reading, or a `+` stream that is not
/// writing, takes them, a buffer given first when it has none yet. They go just before `_ptr`,
/// `_cnt` counting them, and the end of the file is cleared. At the buffer's start, a stream
/// holding nothing makes room for them: the one character MSDN guarantees ungetc; one holding
/// something there, a character already pushed back, has no room (false). Characters read from
/// the buffer leave room for as many pushed back.
fn unget(bytes: &[u8], s: &mut File) -> bool {
    if s.flag & IOREAD == 0 && (s.flag & IORW == 0 || s.flag & IOWRT != 0) {
        return false;
    }
    if s.flag & BUFFERED == 0 {
        give_buffer(s);
    }
    let size = bytes.len();
    if (s.ptr as usize).wrapping_sub(s.base as usize) < size {
        if s.cnt != 0 {
            return false;
        }
        // Nothing buffered: the buffer's first bytes are free (its size is two at least).
        s.ptr = s.base.wrapping_add(size);
    }
    // SAFETY: a `FILE` the C runtime keeps (see `with_stream`): the `size` bytes before `_ptr` are
    // inside its buffer, above `_base`, and the stream's lock keeps them the call's.
    unsafe {
        s.ptr = s.ptr.sub(size);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), s.ptr, size);
    }
    s.cnt += size as i32;
    s.flag &= !IOEOF;
    s.flag |= IOREAD;
    true
}

/// A wide character pushed back into the stream (VC6's `_ungetwc_lk`), as [`get_wide`] reads it
/// back: in text mode its byte in the LC_CTYPE locale's code page, as wctomb converts it (one it
/// lacks is refused, errno EILSEQ); in binary mode its two bytes, low first.
fn unget_wide(c: u16, s: &mut File, text: bool) -> bool {
    if text {
        match ctype::wide_to_byte(c) {
            Some(byte) => unget(&[byte], s),
            None => {
                set_errno(EILSEQ);
                false
            }
        }
    } else {
        unget(&c.to_le_bytes(), s)
    }
}

/// ungetc: `c` (as an unsigned char) pushed back into the stream, the next character read
/// ([`unget`]); answers it, or EOF when `c` is EOF or the stream takes nothing.
///
/// # Safety
///
/// `stream` is null or a stream.
#[unsafe(export_name = "f2k_export_ungetc")]
pub unsafe extern "C" fn ungetc(c: i32, stream: *mut File) -> i32 {
    if c == EOF || stream.is_null() {
        return EOF;
    }
    let body = |s: &mut File, _| {
        if unget(&[c as u8], s) {
            c & 0xFF
        } else {
            EOF
        }
    };
    // SAFETY: the caller's stream.
    unsafe { with_stream(stream, body) }
}

/// ungetwc: the wide character `c` pushed back into the stream ([`unget_wide`], as the
/// descriptor's mode takes it); answers it, or WEOF when `c` is WEOF or the stream takes nothing.
///
/// # Safety
///
/// `stream` is null or a stream.
#[unsafe(export_name = "f2k_export_ungetwc")]
pub unsafe extern "C" fn ungetwc(c: u32, stream: *mut File) -> u32 {
    let c = c as u16;
    if c == ctype::WEOF || stream.is_null() {
        return ctype::WEOF.into();
    }
    let body = |s: &mut File, _| {
        let text = s.flag & IOSTRG == 0 && lowio::is_text(s.file);
        if unget_wide(c, s, text) {
            c.into()
        } else {
            ctype::WEOF.into()
        }
    };
    // SAFETY: the caller's stream.
    unsafe { with_stream(stream, body) }
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

    /// VC6 reads the bounded formatters' count as an int: a count past INT_MAX, `(size_t)-1`
    /// among them, is no room at all — -1 for any text and nothing written, not even the NUL (an
    /// empty text is 0) — never a licence to write past the buffer.
    #[test]
    fn a_count_past_int_max_is_no_room() {
        let list = 42u32.to_ne_bytes();
        for count in [usize::MAX, 0x8000_0000, i32::MAX as usize + 1] {
            let mut out = [b'#'; 8];
            // SAFETY: a buffer of 8 bytes, of which the count offers none; the list holds what the
            // format consumes.
            let n =
                unsafe { snprintf_va(out.as_mut_ptr(), count, b"%d\0".as_ptr(), list.as_ptr()) };
            assert_eq!((n, out), (-1, [b'#'; 8]), "count {count:#x}");
            // SAFETY: as above, the format consuming nothing.
            let n = unsafe { snprintf_va(out.as_mut_ptr(), count, b"\0".as_ptr(), list.as_ptr()) };
            assert_eq!((n, out), (0, [b'#'; 8]), "count {count:#x}, an empty text");
            let mut wide = [b'#' as u16; 8];
            let format = [u16::from(b'%'), u16::from(b'd'), 0];
            // SAFETY: as above, in wide units.
            let n =
                unsafe { snwprintf_va(wide.as_mut_ptr(), count, format.as_ptr(), list.as_ptr()) };
            assert_eq!((n, wide), (-1, [b'#' as u16; 8]), "count {count:#x}, wide");
        }
    }

    /// strings' wformat block: vswprintf is swprintf over a `va_list` (laid out as the host's: a
    /// pointer takes its own width).
    #[test]
    fn vswprintf_takes_a_va_list() {
        use rtl::testing::wide_z;
        let ab = wide_z("ab");
        let mut list = Vec::new();
        list.extend((-7i32).to_ne_bytes());
        list.extend(42u32.to_ne_bytes());
        list.extend(255u32.to_ne_bytes());
        list.extend((ab.as_ptr() as usize).to_ne_bytes());
        list.extend(('z' as u32).to_ne_bytes());
        let format = wide_z("%d|%u|%x|%5s|%-3c|%%");
        let mut out = [b'#' as u16; 32];
        // SAFETY: a buffer of 32 units; the list holds what the format consumes.
        let n = unsafe { vswprintf(out.as_mut_ptr(), format.as_ptr(), list.as_ptr()) };
        assert_eq!(n, 20);
        assert_eq!(
            String::from_utf16_lossy(&out[..22]),
            "-7|42|ff|   ab|z  |%\0#"
        );
        // SAFETY: as above, an empty format and no arguments.
        let n = unsafe { vswprintf(out.as_mut_ptr(), wide_z("").as_ptr(), list.as_ptr()) };
        assert_eq!((n, out[0]), (0, 0));
    }

    /// vsprintf, vfprintf and vfwprintf are sprintf, fprintf and fwprintf over a `va_list` (laid
    /// out as the host's: a pointer takes its own width): the text, its NUL after it in vsprintf's
    /// buffer, and the count; the streams' text buffered, a wide character a descriptor that is
    /// not open in text mode takes as its two bytes.
    #[test]
    fn the_va_list_forms_format_as_their_variadic_ones() {
        use rtl::testing::wide_z;
        let ab = b"ab\0";
        let mut list = Vec::new();
        list.extend((-7i32).to_ne_bytes());
        list.extend((ab.as_ptr() as usize).to_ne_bytes());
        list.extend(0x2Au32.to_ne_bytes());
        let mut out = [b'#'; 16];
        // SAFETY: a buffer of 16 bytes; the list holds what the format consumes.
        let n = unsafe { vsprintf(out.as_mut_ptr(), b"%d|%4s|%#x\0".as_ptr(), list.as_ptr()) };
        assert_eq!((n, &out[..14]), (12, &b"-7|  ab|0x2a\0#"[..]));
        // SAFETY: as above, an empty format.
        let n = unsafe { vsprintf(out.as_mut_ptr(), b"\0".as_ptr(), list.as_ptr()) };
        assert_eq!((n, out[0]), (0, 0));

        let mut buffer = [0u8; 32];
        let mut file = writing(&mut buffer);
        let stream = core::ptr::addr_of_mut!(file);
        // SAFETY: the test's stream; the list as above.
        let n = unsafe { vfprintf(stream, b"%d|%s\0".as_ptr(), list.as_ptr()) };
        // SAFETY: the test's stream.
        assert_eq!((n, unsafe { pending(&*stream).1 }), (5, &b"-7|ab"[..]));

        let mut buffer = [0u8; 32];
        let mut file = writing(&mut buffer);
        let stream = core::ptr::addr_of_mut!(file);
        let mut list = Vec::new();
        list.extend(5u32.to_ne_bytes());
        // SAFETY: the test's stream; the list holds what the format consumes.
        let n = unsafe { vfwprintf(stream, wide_z("%d!").as_ptr(), list.as_ptr()) };
        // SAFETY: the test's stream.
        assert_eq!((n, unsafe { pending(&*stream).1 }), (2, &b"5\0!\0"[..]));
    }

    /// strings' wformat block's files: in text mode each wide character as the C locale's code
    /// page has it (below U+0100), one without a byte ending the output; in binary mode each
    /// character's two bytes, low first.
    #[test]
    fn wide_output_takes_the_descriptors_mode() {
        use rtl::testing::wide_z;

        use crate::format::tests::{units_of, List};
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
                &units_of(&wide_z(format)),
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
            assert_eq!(
                file_position(&*stream, 10, true, || true, || false).unwrap(),
                0
            );
            assert_eq!(fread(out.as_mut_ptr(), 1, 4, stream), 4);
            assert_eq!(&out[..4], b"ab\nc");
            assert_eq!(
                file_position(&*stream, 10, true, || true, || false).unwrap(),
                5
            );
            assert_eq!(fread(out.as_mut_ptr(), 3, 1, stream), 1);
            assert_eq!(&out[..3], b"d\ne");
            assert_eq!(
                file_position(&*stream, 10, true, || true, || false).unwrap(),
                9
            );
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
            assert_eq!(
                file_position(&*stream, 10, false, || true, || false).unwrap(),
                4
            );
        }
    }

    /// Streams past `_iob`'s 20 are made of the heap as the ones before them are taken (fd's
    /// nfiles capture: 40 files open at once), each found again by its address; _flushall
    /// flushes every stream in use (the three standard ones too: the capture's 43 for 40 files),
    /// and _fcloseall closes all but those three and frees the heap's. (Their descriptors are not
    /// open on the host, so no close succeeds: 0 counted.)
    #[test]
    fn streams_grow_past_iob() {
        let _iob = crate::data::IOB_TESTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::data::open_standard_streams();
        let claimed: Vec<usize> = (0..40)
            .map(|fd| claim(IOWRT, 100 + fd).expect("a free stream"))
            .collect();
        assert_eq!(claimed, (3..43).collect::<Vec<_>>());
        for &index in &claimed {
            let stream = stream_at(index);
            assert!(!stream.is_null());
            assert_eq!(index_of(stream), Some(index));
        }
        assert_eq!(index_of(core::ptr::null_mut()), None);
        assert_eq!(flushall(), 43);
        assert_eq!(fcloseall(), 0);
        assert!(EXTRA
            .iter()
            .all(|extra| extra.load(Ordering::Relaxed).is_null()));
        assert!((3..IOB_ENTRIES).all(|index| with_iob(index, |s, _| !in_use(s))));
        assert_eq!(fcloseall(), 0);
        assert_eq!(claim(IOREAD, 7), Some(3));
        with_iob(3, |s, _| *s = File::UNUSED);
    }

    /// fopen's mode as VC6 reads it: a first letter `r`, `w` or `a`, then one of each kind at
    /// most, the reading stopping at an unknown letter or a second of a kind (fd's modes capture:
    /// "rzb" and "rtb" text, "rbt" binary, "q" and "" none).
    #[test]
    fn fopen_reads_its_mode_as_vc6_does() {
        use lowio::{O_APPEND, O_BINARY, O_CREAT, O_RDONLY, O_RDWR, O_TEXT, O_TRUNC, O_WRONLY};
        let mode = |text: &[u8]| open_mode(text);
        assert_eq!(mode(b"r"), Some((O_RDONLY, IOREAD)));
        assert_eq!(mode(b"rtb"), Some((O_TEXT, IOREAD)));
        assert_eq!(mode(b"rbt"), Some((O_BINARY, IOREAD)));
        assert_eq!(mode(b"rzb"), Some((O_RDONLY, IOREAD)));
        assert_eq!(mode(b"r+b"), Some((O_RDWR | O_BINARY, IORW)));
        assert_eq!(mode(b"r++b"), Some((O_RDWR, IORW)));
        assert_eq!(
            mode(b"wb+"),
            Some((O_RDWR | O_CREAT | O_TRUNC | O_BINARY, IORW))
        );
        assert_eq!(
            mode(b"a+D"),
            Some((O_RDWR | O_CREAT | O_APPEND | lowio::O_TEMPORARY, IORW))
        );
        assert_eq!(
            mode(b"wTDcS"),
            Some((
                O_WRONLY
                    | O_CREAT
                    | O_TRUNC
                    | lowio::O_SHORT_LIVED
                    | lowio::O_TEMPORARY
                    | lowio::O_SEQUENTIAL,
                IOWRT
            ))
        );
        assert_eq!(mode(b"rcnb"), Some((O_RDONLY, IOREAD)));
        assert_eq!(mode(b"rSRb"), Some((lowio::O_SEQUENTIAL, IOREAD)));
        assert_eq!(mode(b"q"), None);
        assert_eq!(mode(b""), None);
    }

    /// ftell after each byte read of a text file wholly buffered, as fd's textmode capture traces
    /// it: the fill's bytes counted back from the file's end with each LF as CR LF (and the
    /// Ctrl-Z it stopped at), so "ab\r\ncd\r\n" reads 1 2 4 5 6 8, a file of bare LFs reads short
    /// (-2 0 1 3 4 6), and "a\r\nb^Zcd" 3 5 7.
    #[test]
    fn ftell_reckons_a_text_fill_as_vc6_does() {
        let trace = |held: &[u8], at: i32, flag: i32| {
            let mut buffer = held.to_vec();
            let mut file = File {
                flag: IOREAD | IOMYBUF | flag,
                ..reading(&mut buffer)
            };
            (0..held.len())
                .map(|_| {
                    get(&mut file);
                    file_position(&file, at, true, || true, || panic!("at the end")).unwrap()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(trace(b"ab\ncd\n", 8, 0), [1, 2, 4, 5, 6, 8]);
        assert_eq!(trace(b"a\nb\nc\n", 6, 0), [-2, 0, 1, 3, 4, 6]);
        assert_eq!(trace(b"a\nb", 7, IOCTRLZ), [3, 5, 7]);
    }

    /// ftell of a text stream whose fill did not reach the file's end: the fill took its buffer's
    /// size from the file (512 after fseek's small fill), one more when its first LF's CR came
    /// before it; nothing buffered is the descriptor's position; one neither reading nor writing,
    /// nor open for update, is none.
    #[test]
    fn ftell_counts_a_full_fill_as_its_buffer() {
        let mut buffer = [b'x'; 16];
        let mut file = File {
            flag: IOREAD | IOYOURBUF,
            ..reading(&mut buffer)
        };
        get(&mut file);
        assert_eq!(
            file_position(&file, 100, true, || false, || false),
            Some(85)
        );
        assert_eq!(file_position(&file, 100, true, || false, || true), Some(84));
        file.flag = IOREAD | IOMYBUF;
        assert_eq!(
            file_position(&file, 1000, true, || false, || false),
            Some(489)
        );
        file.cnt = 0;
        assert_eq!(
            file_position(&file, 100, true, || false, || false),
            Some(100)
        );
        file.flag = IOMYBUF;
        assert_eq!(file_position(&file, 100, true, || false, || false), None);
        file.flag = IONBF;
        file.cnt = 3;
        assert_eq!(
            file_position(&file, 100, true, || false, || false),
            Some(97)
        );
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
            assert_eq!(
                file_position(&*stream, 0, true, || true, || false).unwrap(),
                0
            );
            assert_eq!(fwrite(b"ab\ncd\n".as_ptr(), 1, 6, stream), 6);
            assert_eq!(
                file_position(&*stream, 0, true, || true, || false).unwrap(),
                8
            );
            assert_eq!(fwrite(b"xy\nz".as_ptr(), 2, 2, stream), 2);
            assert_eq!(
                file_position(&*stream, 0, true, || true, || false).unwrap(),
                13
            );
            assert_eq!(
                file_position(&*stream, 0, false, || true, || false).unwrap(),
                10
            );
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

    /// ungetc's one character: a stream that has read nothing takes one (a buffer given first),
    /// read back next, and refuses a second at the buffer's start; one that has read from its
    /// buffer takes as many as it read, last pushed first read. EOF itself, and a stream writing,
    /// take nothing. The end of the file is cleared.
    #[test]
    fn ungetc_pushes_back_one_character_at_least() {
        let mut file = File {
            flag: IOREAD | IOEOF,
            file: 2000,
            ..File::UNUSED
        };
        let stream = core::ptr::addr_of_mut!(file);
        // SAFETY: the test's stream.
        unsafe {
            assert_eq!(ungetc(EOF, stream), EOF);
            assert_eq!(ungetc(0x141, stream), 0x41);
            assert_eq!((*stream).flag & (IOEOF | IOMYBUF), IOMYBUF);
            assert_eq!(ungetc(b'z' as i32, stream), EOF, "a second at the start");
            assert_eq!(get(&mut *stream), b'A' as i32);
            assert_eq!((*stream).cnt, 0);
            free_buffer(&mut *stream);
        }

        let mut text = *b"abcd";
        let mut file = reading(&mut text);
        let stream = core::ptr::addr_of_mut!(file);
        // SAFETY: the test's stream and buffer.
        unsafe {
            assert_eq!(get(&mut *stream), b'a' as i32);
            assert_eq!(get(&mut *stream), b'b' as i32);
            assert_eq!(ungetc(b'x' as i32, stream), b'x' as i32);
            assert_eq!(ungetc(b'y' as i32, stream), b'y' as i32);
            assert_eq!(
                ungetc(b'q' as i32, stream),
                EOF,
                "no room before the buffer"
            );
            let read: Vec<i32> = (0..4).map(|_| get(&mut *stream)).collect();
            assert_eq!(read, [b'y', b'x', b'c', b'd'].map(i32::from));
        }

        let mut buffer = [0u8; 8];
        let mut file = writing(&mut buffer);
        let stream = core::ptr::addr_of_mut!(file);
        // SAFETY: the test's stream.
        unsafe { assert_eq!(ungetc(b'x' as i32, stream), EOF, "a stream writing") };
        // SAFETY: a null stream.
        unsafe { assert_eq!(ungetc(b'x' as i32, core::ptr::null_mut()), EOF) };
    }

    /// A `+` stream that is neither reading nor writing yet takes a character back, and reads.
    #[test]
    fn ungetc_starts_a_plus_stream_reading() {
        let mut buffer = [0u8; 4];
        let mut file = File {
            flag: IORW | IOYOURBUF,
            cnt: 0,
            ..reading(&mut buffer)
        };
        let stream = core::ptr::addr_of_mut!(file);
        // SAFETY: the test's stream.
        unsafe {
            assert_eq!(ungetc(b'k' as i32, stream), b'k' as i32);
            assert_eq!((*stream).flag & (IOREAD | IOWRT), IOREAD);
            assert_eq!(get(&mut *stream), b'k' as i32);
        }
    }

    /// ungetwc pushes back what get_wide reads: in text mode a byte, as the "C" locale's code page
    /// has the character (one it lacks refused, errno EILSEQ); in binary mode two bytes, low
    /// first. WEOF is refused.
    #[test]
    fn ungetwc_pushes_back_as_the_mode_reads() {
        let _locale = ctype::tests::LOCALE.lock().unwrap();
        // SAFETY: setlocale over a NUL-terminated name.
        unsafe { ctype::setlocale(0, b"C\0".as_ptr()) };
        let mut text = *b"ab";
        let mut file = reading(&mut text);
        assert_eq!(get_wide(&mut file, true), Some(0x61));
        assert!(unget_wide(0xE9, &mut file, true));
        assert_eq!(get_wide(&mut file, true), Some(0xE9));
        set_errno(0);
        assert!(!unget_wide(0x3B1, &mut file, true));
        assert_eq!(crate::thread::errno(), EILSEQ);
        assert_eq!(get_wide(&mut file, true), Some(0x62));

        let mut binary = *b"a\0b\0";
        let mut file = reading(&mut binary);
        assert_eq!(get_wide(&mut file, false), Some(0x61));
        assert!(unget_wide(0x3B1, &mut file, false));
        assert!(!unget_wide(0x41, &mut file, false), "no room for two more");
        assert_eq!(get_wide(&mut file, false), Some(0x3B1));
        assert_eq!(get_wide(&mut file, false), Some(0x62));

        let stream = core::ptr::addr_of_mut!(file);
        // SAFETY: the test's stream.
        unsafe { assert_eq!(ungetwc(0xFFFF, stream), 0xFFFF) };
    }

    /// The pointers a scan's fields store through, as a `va_list` (laid out as the host's).
    fn pointers(list: &[usize]) -> Vec<u8> {
        list.iter().flat_map(|p| p.to_ne_bytes()).collect()
    }

    /// fscanf reads the stream's bytes through its buffer, and the character it reads ahead and
    /// does not take goes back for the next read: the newline after a word, the letter after a
    /// number. At the end, before any conversion, EOF; a null stream is EOF too.
    #[test]
    fn fscanf_leaves_the_character_it_did_not_take() {
        let mut text = *b"12 ab\n7x";
        let mut file = reading(&mut text);
        let stream = core::ptr::addr_of_mut!(file);
        let (mut n, mut word) = (0i32, [0u8; 8]);
        let args = pointers(&[&mut n as *mut i32 as usize, word.as_mut_ptr() as usize]);
        // SAFETY: the test's stream; the list holds the pointers the formats store through.
        unsafe {
            assert_eq!(fscanf_va(stream, b"%d %s\0".as_ptr(), args.as_ptr()), 2);
            assert_eq!((n, &word[..3]), (12, &b"ab\0"[..]));
            assert_eq!((*stream).ptr.read(), b'\n', "the newline is the next byte");
            assert_eq!(fscanf_va(stream, b"%d\0".as_ptr(), args.as_ptr()), 1);
            assert_eq!(n, 7);
            assert_eq!(get(&mut *stream), b'x' as i32);
            // The buffer is spent and the refill fails: the end, before any conversion.
            assert_eq!(fscanf_va(stream, b"%d\0".as_ptr(), args.as_ptr()), EOF);
            assert_eq!(n, 7);
            assert_eq!(
                fscanf_va(core::ptr::null_mut(), b"%d\0".as_ptr(), args.as_ptr()),
                EOF
            );
        }
    }

    /// fwscanf reads the stream's wide characters as fgetws does (a descriptor not open in text
    /// mode: two bytes each), its `%c` a wide character; a wide scan at the end answers 0.
    #[test]
    fn fwscanf_reads_wide_characters() {
        use rtl::testing::wide_z;
        let mut binary = *b"1\0 \0z\0";
        let mut file = reading(&mut binary);
        let stream = core::ptr::addr_of_mut!(file);
        let (mut n, mut c) = (0i32, [0u16; 2]);
        let args = pointers(&[&mut n as *mut i32 as usize, c.as_mut_ptr() as usize]);
        // SAFETY: the test's stream; the list holds the pointers the formats store through.
        unsafe {
            assert_eq!(
                fwscanf_va(stream, wide_z("%d %c").as_ptr(), args.as_ptr()),
                2
            );
            assert_eq!((n, c[0]), (1, b'z' as u16));
            assert_eq!(fwscanf_va(stream, wide_z("%d").as_ptr(), args.as_ptr()), 0);
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
