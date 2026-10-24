//! msvcrt's exported variables: storage in the DLL's own writable data that programs reach through
//! their import address tables (`_iob[1]` is the address the table holds, plus 32), as Windows
//! 2000's msvcrt exports them. Each is a static named `f2k_export_<Name>`, which the
//! module-definition file exports under its name as DATA (its spec record says `data = true`).
//!
//! Their sizes are the interface's (MSVC 6's headers): `_iob` is the 20 `FILE`s of stdio.h's
//! `struct _iobuf` (8 dwords each: stdin, stdout and stderr first), the others are `int`s. They
//! start zeroed, in `.data` (an exported variable keeps file bytes: the kernel's checks read the
//! DLL's exports from its file, and the zero-initialized data after them has none). The DLL's
//! process attach gives `_iob` its first streams ([`open_standard_streams`]); `_fmode` and
//! `_adjust_fdiv` stay zero (text mode; no FDIV workaround).
//!
//! [`Global`] is the same storage for the C runtime's own process-wide state.

use core::cell::UnsafeCell;

/// An exported variable. The cell makes it mutable, so the compiler places it in the DLL's
/// writable data, never its read-only data: the DLL and the programs importing it both write it,
/// each process its own copy (an image's writable pages are copy-on-write).
#[repr(transparent)]
pub struct Exported<T>(UnsafeCell<T>);

// SAFETY: the C runtime's variables are shared by every thread of the process, as the platform's
// are; their users synchronize (or not) as the C runtime's contract says.
unsafe impl<T> Sync for Exported<T> {}

impl<T> Exported<T> {
    pub const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    /// The variable's address, as an importer sees it.
    pub const fn get(&self) -> *mut T {
        self.0.get()
    }
}

/// A process-wide variable of the C runtime's own: shared by every thread, guarded where it needs
/// to be by the C runtime's lock ([`crate::thread::Locked`]).
#[repr(transparent)]
pub struct Global<T>(UnsafeCell<T>);

// SAFETY: as Exported's; the C runtime's lock serializes the state that needs it.
unsafe impl<T> Sync for Global<T> {}

impl<T> Global<T> {
    pub const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    /// The variable's address.
    pub const fn get(&self) -> *mut T {
        self.0.get()
    }
}

impl<T: Copy> Global<T> {
    /// The variable's value.
    pub fn read(&self) -> T {
        // SAFETY: a plain read of the process's own variable.
        unsafe { self.0.get().read() }
    }

    /// The variable set to `value`.
    pub fn write(&self, value: T) {
        // SAFETY: a plain write of the process's own variable.
        unsafe { self.0.get().write(value) }
    }
}

/// A stdio stream: MSVC 6's `FILE` (stdio.h's `struct _iobuf`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct File {
    /// `_ptr`: the next character in the buffer.
    pub ptr: *mut u8,
    /// `_cnt`: the characters left in the buffer (to read, or room to write).
    pub cnt: i32,
    /// `_base`: the buffer.
    pub base: *mut u8,
    /// `_flag`: the stream's `_IO*` flags.
    pub flag: i32,
    /// `_file`: its file descriptor.
    pub file: i32,
    /// `_charbuf`: the one-character buffer of an unbuffered stream.
    pub charbuf: i32,
    /// `_bufsiz`: the buffer's size.
    pub bufsiz: i32,
    /// `_tmpfname`: a temporary file's name.
    pub tmpfname: *mut u8,
}

impl File {
    /// A stream not in use.
    pub const UNUSED: File = File {
        ptr: core::ptr::null_mut(),
        cnt: 0,
        base: core::ptr::null_mut(),
        flag: 0,
        file: 0,
        charbuf: 0,
        bufsiz: 0,
        tmpfname: core::ptr::null_mut(),
    };
}

/// The streams `_iob` holds: stdin, stdout, stderr, then the ones _fdopen hands out.
pub const IOB_ENTRIES: usize = 20;

/// The size of the buffers the C runtime gives streams itself (fd's capture: 4096 bytes).
pub const STREAM_BUFFER: usize = 4096;

/// stdin's buffer, the DLL's own from the start (its stream says so: `_IOYOURBUF`).
pub static STDIN_BUFFER: Global<[u8; STREAM_BUFFER]> = Global::new([0; STREAM_BUFFER]);

/// The `_flag` bits `_iob`'s first streams start with: stdio.h's `_IOREAD` and `_IOWRT`, and
/// `_IOYOURBUF` (a buffer the stream does not own).
const IOREAD: i32 = 0x0001;
const IOWRT: i32 = 0x0002;
const IOYOURBUF: i32 = 0x0100;

/// `_iob`: the stdio streams.
#[unsafe(export_name = "f2k_export__iob")]
#[cfg_attr(target_arch = "x86", unsafe(link_section = ".data"))]
pub static IOB: Exported<[File; IOB_ENTRIES]> = Exported::new([File::UNUSED; IOB_ENTRIES]);

/// The DLL's process attach: stdin, stdout and stderr open on descriptors 0, 1 and 2, as Windows
/// 2000's msvcrt has them before `main` (fd's capture): stdin reading through a 4096-byte buffer
/// of the DLL's own, stdout and stderr writing, unbuffered until their first output.
pub fn open_standard_streams() {
    // SAFETY: the process's streams, before any thread uses them.
    let streams = unsafe { &mut *IOB.get() };
    streams[0] = File {
        ptr: STDIN_BUFFER.get() as *mut u8,
        base: STDIN_BUFFER.get() as *mut u8,
        flag: IOREAD | IOYOURBUF,
        bufsiz: STREAM_BUFFER as i32,
        ..File::UNUSED
    };
    streams[1] = File {
        flag: IOWRT,
        file: 1,
        ..File::UNUSED
    };
    streams[2] = File {
        flag: IOWRT,
        file: 2,
        ..File::UNUSED
    };
}

/// `_fmode`: the default translation mode of the files a program opens (`_O_TEXT` or
/// `_O_BINARY`; zero, text, until the program's start-up sets it).
#[unsafe(export_name = "f2k_export__fmode")]
#[cfg_attr(target_arch = "x86", unsafe(link_section = ".data"))]
pub static FMODE: Exported<i32> = Exported::new(0);

/// `_adjust_fdiv`: whether the floating-point division needs the Pentium FDIV workaround (programs
/// built with /QIfdiv read it).
#[unsafe(export_name = "f2k_export__adjust_fdiv")]
#[cfg_attr(target_arch = "x86", unsafe(link_section = ".data"))]
pub static ADJUST_FDIV: Exported<i32> = Exported::new(0);

// The interface's sizes, on the DLL's own target (the host's pointers are wider).
#[cfg(target_arch = "x86")]
const _: () = {
    assert!(core::mem::size_of::<File>() == 32);
    assert!(core::mem::size_of::<[File; IOB_ENTRIES]>() == 640);
    assert!(core::mem::size_of::<Exported<i32>>() == 4);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// `_iob` starts as fd's capture shows it before `main`: stdin reading through the DLL's own
    /// 4096-byte buffer (`_flag` 0x101), stdout and stderr writing without one (0x2); the other
    /// streams unused, and the ints zero.
    #[test]
    fn the_variables_start_as_captured() {
        open_standard_streams();
        // SAFETY: the test's process's own copy, read on one thread.
        unsafe {
            let streams = &*IOB.get();
            assert_eq!(streams.len(), 20);
            assert_eq!(
                (streams[0].flag, streams[0].file, streams[0].bufsiz),
                (0x101, 0, 4096)
            );
            assert_eq!(streams[0].base, STDIN_BUFFER.get() as *mut u8);
            assert_eq!((streams[0].ptr, streams[0].cnt), (streams[0].base, 0));
            for fd in [1, 2] {
                let stream = &streams[fd];
                assert_eq!(
                    (stream.flag, stream.file, stream.cnt, stream.bufsiz),
                    (2, fd as i32, 0, 0)
                );
                assert!(stream.base.is_null());
            }
            assert!(streams[3..]
                .iter()
                .all(|file| file.ptr.is_null() && file.flag == 0));
            assert_eq!(*FMODE.get(), 0);
            assert_eq!(*ADJUST_FDIV.get(), 0);
        }
        assert_ne!(FMODE.get(), ADJUST_FDIV.get());
    }
}
