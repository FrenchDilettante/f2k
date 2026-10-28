//! advapi32's user-mode code: the bodies of its exports (the registry first), as Windows 2000's
//! advapi32 runs them, over ntdll's and kernel32's exports ([`imports`], as Windows 2000's
//! advapi32 imports them).
//!
//! An export here is an `extern "system"` function named `f2k_export_<Name>`, which the DLL's
//! module-definition file exports under its name (build-support/stubs.rs finds them; the export
//! spec declares it `impl = { native = "<Name>" }`). The DLL (src/main.rs) links this library; the
//! host tests run its code against [`imports`]' stand-ins.
//!
//! An export converts its caller's pointers once, on entry: a string into a slice of its units, a
//! buffer into a slice ([`caller_bytes`], [`caller_bytes_mut`]), an out parameter into an [`Out`].
//! The code below the exports is safe.
//!
//! The exports not written yet are stubs: their generated bodies log the call and fail ([`stub`]).

#![cfg_attr(not(test), no_std)]

use core::marker::PhantomData;
use core::ptr::NonNull;

pub mod imports;
pub mod registry;
pub mod stub;

// The exports' descriptions (`spec`) and the stubbed exports' bodies, generated from exports.toml
// (tools/exportgen; see `stub`).
include!(concat!(env!("OUT_DIR"), "/exports.rs"));

/// A caller's out parameter: the place of a `T` it gave the address of, written (and read, for an
/// in-out one) unaligned. x86 tolerates a misaligned address, so a Windows program may pass one.
pub struct Out<'a, T> {
    at: NonNull<T>,
    place: PhantomData<&'a mut T>,
}

impl<'a, T: Copy> Out<'a, T> {
    /// The out parameter at `at`: none for null.
    ///
    /// # Safety
    ///
    /// `at` is null, or the address (at any alignment) of a `T` the call may read and write for
    /// `'a`, which nothing else reaches meanwhile.
    pub unsafe fn new(at: *mut T) -> Option<Self> {
        NonNull::new(at).map(|at| Out {
            at,
            place: PhantomData,
        })
    }

    /// The value the place holds.
    pub fn get(&self) -> T {
        // SAFETY: `new`'s contract: a readable `T`, read unaligned.
        unsafe { self.at.as_ptr().read_unaligned() }
    }

    /// Write `value` to the place.
    pub fn set(&mut self, value: T) {
        // SAFETY: `new`'s contract: a writable `T`, written unaligned.
        unsafe { self.at.as_ptr().write_unaligned(value) }
    }
}

impl<'a, T> From<&'a mut T> for Out<'a, T> {
    /// A place of the code's own as an out parameter.
    fn from(place: &'a mut T) -> Self {
        Out {
            at: NonNull::from(place),
            place: PhantomData,
        }
    }
}

/// The caller's buffer of `length` bytes at `at`, to read: none for a null address with a length
/// (a buffer the call cannot reach), the empty slice for no length.
///
/// # Safety
///
/// `at` is null, or holds `length` bytes the call may read for `'a`, which nothing writes
/// meanwhile.
pub unsafe fn caller_bytes<'a>(at: *const u8, length: usize) -> Option<&'a [u8]> {
    if length == 0 {
        return Some(&[]);
    }
    if at.is_null() {
        return None;
    }
    // SAFETY: the caller's contract: `length` readable bytes.
    Some(unsafe { core::slice::from_raw_parts(at, length) })
}

/// The caller's buffer of `length` bytes at `at`, to write: none for a null address with a length,
/// the empty slice for no length.
///
/// # Safety
///
/// `at` is null, or holds `length` bytes the call may read and write for `'a`, which nothing else
/// reaches meanwhile.
pub unsafe fn caller_bytes_mut<'a>(at: *mut u8, length: usize) -> Option<&'a mut [u8]> {
    if length == 0 {
        return Some(&mut []);
    }
    if at.is_null() {
        return None;
    }
    // SAFETY: the caller's contract: `length` writable bytes, ours for the call.
    Some(unsafe { core::slice::from_raw_parts_mut(at, length) })
}
