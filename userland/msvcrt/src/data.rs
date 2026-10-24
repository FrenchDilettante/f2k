//! msvcrt's exported variables: storage in the DLL's own writable data that programs reach through
//! their import address tables (`_iob[1]` is the address the table holds, plus 32), as Windows
//! 2000's msvcrt exports them. Each is a static named `f2k_export_<Name>`, which the
//! module-definition file exports under its name as DATA (its spec record says `data = true`).
//!
//! They start zeroed: the C runtime's start-up gives them their values. Their sizes are the
//! interface's (MSVC 6's headers): `_iob` is the 20 `FILE`s of stdio.h's `struct _iobuf` (8
//! dwords each: stdin, stdout and stderr first), the others are `int`s.

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

/// A stdio stream: MSVC 6's `FILE` (stdio.h's `struct _iobuf`).
#[repr(C)]
pub struct File {
    /// `_ptr`: the next character in the buffer.
    pub ptr: *mut u8,
    /// `_cnt`: the characters left in the buffer.
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

/// The streams `_iob` holds: stdin, stdout, stderr, then the ones fopen hands out.
pub const IOB_ENTRIES: usize = 20;

/// `_iob`: the stdio streams.
#[unsafe(export_name = "f2k_export__iob")]
pub static IOB: Exported<[File; IOB_ENTRIES]> = Exported::new([File::UNUSED; IOB_ENTRIES]);

/// `_fmode`: the default translation mode of the files a program opens (`_O_TEXT` or
/// `_O_BINARY`).
#[unsafe(export_name = "f2k_export__fmode")]
pub static FMODE: Exported<i32> = Exported::new(0);

/// `_adjust_fdiv`: whether the floating-point division needs the Pentium FDIV workaround (programs
/// built with /QIfdiv read it).
#[unsafe(export_name = "f2k_export__adjust_fdiv")]
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

    /// The variables start zeroed, each its own storage, `_iob` its 20 streams (their sizes are the
    /// target's, asserted at its build above: the host's pointers are wider).
    #[test]
    fn the_variables_start_zeroed() {
        // SAFETY: the test's process's own copy, read on one thread.
        unsafe {
            assert!((*IOB.get()).iter().all(|file| file.ptr.is_null()
                && file.cnt == 0
                && file.flag == 0
                && file.file == 0
                && file.tmpfname.is_null()));
            assert_eq!(*FMODE.get(), 0);
            assert_eq!(*ADJUST_FDIV.get(), 0);
        }
        // SAFETY: as above.
        assert_eq!(unsafe { (*IOB.get()).len() }, 20);
        assert_ne!(FMODE.get(), ADJUST_FDIV.get());
    }
}
