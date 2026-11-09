//! gdi32's user-mode code: the bodies of its exports (the screen DC, its stock objects, its colors
//! and modes and its pixels, [`dc`]; text and its metrics, [`text`]), as Windows 2000's gdi32
//! runs them, over ntdll's, kernel32's and user32's exports and win32k's services ([`imports`]:
//! as Windows 2000's gdi32 imports the first and enters the kernel itself for the others, through
//! its own stubs).
//!
//! An export here is an `extern "system"` function named `f2k_export_<Name>`, which the DLL's
//! module-definition file exports under its name (build-support/stubs.rs finds them; the export
//! spec declares it `impl = { native = "<Name>" }`). The DLL (src/main.rs) links this library; the
//! host tests run its code against [`imports`]' stand-ins.
//!
//! An export converts its caller's pointers once, on entry: a narrow string it converts into a
//! slice, memory a service reads or writes for the caller into an [`imports::Caller`] handed to
//! the kernel unread, an out parameter into an [`Out`]. The code below the exports is safe. A
//! service's failure becomes the last error ([`answered`]); a success leaves the last error as it
//! was.
//!
//! The exports not written yet that the corpus imports are stubs: their generated bodies log the
//! call and fail, as do the paths an implemented export does not handle ([`stub`]). The rest are
//! not exported (their records are the catalogue's).

#![cfg_attr(not(test), no_std)]

pub mod dc;
pub mod imports;
pub mod stub;
pub mod text;

/// A caller's out parameter, as every system DLL's exports take them.
pub use rtl::edge::Out;
use rtl::status::NtStatus;

// The exports' descriptions (`spec`) and the stubbed exports' bodies, generated from exports.toml
// (tools/exportgen; see `stub`).
include!(concat!(env!("OUT_DIR"), "/exports.rs"));

/// ERROR_INVALID_HANDLE: a handle that names no DC, or no object of the kind the call takes.
pub const ERROR_INVALID_HANDLE: u32 = 6;
/// ERROR_NOT_ENOUGH_MEMORY: a conversion's buffer could not be had.
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
/// ERROR_INVALID_PARAMETER: a count, a mode or a name the call does not take.
pub const ERROR_INVALID_PARAMETER: u32 = 87;

/// A service's answer: its value, or none with the failure's status made the last error (rtl's
/// status table: see [`imports`]).
pub fn answered<T>(answer: Result<T, NtStatus>) -> Option<T> {
    answer
        .map_err(|status| imports::set_last_error(rtl::status::dos_error(status.0)))
        .ok()
}

/// A failure of the call's own: `error` made the last error, nothing answered.
pub fn failed<T>(error: u32) -> Option<T> {
    imports::set_last_error(error);
    None
}

/// The units a narrow string converts into without the heap: its wide form on the stack.
const STACK_UNITS: usize = 256;

/// Run `f` on the wide form of the narrow `bytes` (the ANSI code page's, through ntdll's
/// RtlMultiByteToUnicodeN, as Windows 2000's gdi32 converts), on the stack when it is short and
/// in a block of the process heap otherwise; none, with ERROR_NOT_ENOUGH_MEMORY, when the heap has
/// no room for it.
pub fn with_wide<R>(bytes: &[u8], f: impl FnOnce(&[u16]) -> R) -> Option<R> {
    if bytes.len() <= STACK_UNITS {
        let mut units = [0u16; STACK_UNITS];
        let length = imports::multi_byte_to_unicode(&mut units[..bytes.len()], bytes);
        return Some(f(&units[..length]));
    }
    let Some(mut block) = imports::HeapBlock::new(2 * bytes.len()) else {
        return failed(ERROR_NOT_ENOUGH_MEMORY);
    };
    let units = block.units_mut();
    let length = imports::multi_byte_to_unicode(units, bytes);
    Some(f(&units[..length]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::LAST_ERROR;

    /// A short string converts on the stack, a long one through the heap, each unit its ANSI
    /// byte's (0x80 the euro sign).
    #[test]
    fn narrow_strings_convert_to_wide() {
        let wide = with_wide(b"Hi\x80", |units| units.to_vec()).unwrap();
        assert_eq!(wide, [0x48, 0x69, 0x20AC]);
        let long = std::vec![b'x'; 1000];
        let wide = with_wide(&long, |units| units.to_vec()).unwrap();
        assert_eq!(wide.len(), 1000);
        assert!(wide.iter().all(|&unit| unit == 0x78));
        assert_eq!(with_wide(b"", |units| units.len()), Some(0));
    }

    /// A failed service's status is the last error, through rtl's table.
    #[test]
    fn a_failure_is_the_last_error() {
        LAST_ERROR.with(|error| error.set(0));
        assert_eq!(answered::<u32>(Err(NtStatus(0xC000_0008))), None);
        assert_eq!(LAST_ERROR.with(|error| error.get()), ERROR_INVALID_HANDLE);
        assert_eq!(answered(Ok(5u32)), Some(5));
        assert_eq!(
            LAST_ERROR.with(|error| error.get()),
            ERROR_INVALID_HANDLE,
            "a success leaves it"
        );
    }
}
