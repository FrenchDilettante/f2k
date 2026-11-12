//! The multibyte code page: _setmbcp and _getmbcp, and _ismbblead over the table of each byte's
//! multibyte classes (mbctype.h's `_mbctype`).
//!
//! As msvcrt's capture shows them: a single-byte code page (1252, 437, 850, _MB_CP_SBCS, and the
//! system's OEM and ANSI ones) makes _getmbcp answer 0, as MSDN documents for one ("a return value
//! of 0 indicates that a single byte code page is in use"), and _ismbblead take no byte as a lead
//! byte; a code page that does not exist answers -1, errno untouched, the code page left as it
//! was. _ismbblead reads its argument's low byte. The DLL's initialization sets the system's ANSI
//! code page (MSDN's _setmbcp: the run-time library sets it "at program startup").
//!
//! A double-byte code page takes msvcrt's own tables of its trail bytes as well as GetCPInfo's lead
//! bytes, and F2K carries none: one (a code page whose characters take more than a byte, or one
//! of Windows 2000's double-byte pages that kernel32 lacks) logs as not yet implemented and answers
//! -1, as a code page that does not exist does.
//!
//! The table is read without a lock, as Windows 2000's `_mbctype` is (a program reads it directly
//! through mbctype.h's macros); _setmbcp rewrites it under the multibyte code page's lock.

use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::{AtomicI32, AtomicU8};

use crate::thread::Lock;
use crate::{ctype, kernel32};

/// _setmbcp's pseudo code pages (mbctype.h's).
const MB_CP_SBCS: i32 = 0;
const MB_CP_OEM: i32 = -2;
const MB_CP_ANSI: i32 = -3;
const MB_CP_LOCALE: i32 = -4;

/// `_mbctype`'s classes of a byte: a lead byte, a trail byte (mbctype.h's `_M1` and `_M2`).
const M1: u8 = 0x04;
const M2: u8 = 0x08;

/// Windows 2000's double-byte code pages: Japanese, Simplified Chinese, Korean (Wansung),
/// Traditional Chinese, Korean (Johab).
const DOUBLE_BYTE_PAGES: [u32; 5] = [932, 936, 949, 950, 1361];

/// `_mbctype`: each byte's multibyte classes, its entry the byte's value plus one (the first is
/// EOF's), as mbctype.h lays it out.
static MBCTYPE: [AtomicU8; 257] = [const { AtomicU8::new(0) }; 257];

/// The multibyte code page, 0 for a single-byte one (`__mbcodepage`).
static CODE_PAGE: AtomicI32 = AtomicI32::new(0);

/// The multibyte code page's lock (Windows 2000's msvcrt has one): held while _setmbcp rewrites
/// the table and the code page.
static LOCK: Lock = Lock::new();

/// A single-byte code page set: no byte a lead byte or a trail byte, the code page 0.
fn set_single_byte() {
    let _held = LOCK.hold();
    for class in &MBCTYPE {
        class.fetch_and(!(M1 | M2), Relaxed);
    }
    CODE_PAGE.store(0, Relaxed);
}

/// What a code page is, to _setmbcp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Page {
    SingleByte,
    /// One whose characters take more than a byte.
    Multibyte,
    /// None that exists.
    Unknown,
}

/// The code page `page`, after its pseudo code page is resolved: single-byte, multibyte
/// (GetCPInfo's maximum character size, or one of Windows 2000's double-byte pages kernel32 lacks),
/// or none.
fn classify(page: u32) -> Page {
    if page == 0 {
        return Page::SingleByte;
    }
    match kernel32::cp_info(page) {
        Some(info) if info.max_char_size == 1 => Page::SingleByte,
        Some(_) => Page::Multibyte,
        None if DOUBLE_BYTE_PAGES.contains(&page) => Page::Multibyte,
        None => Page::Unknown,
    }
}

/// A pseudo code page as the code page it stands for.
fn resolve(page: i32) -> u32 {
    match page {
        MB_CP_SBCS => 0,
        MB_CP_OEM => kernel32::oem_code_page(),
        MB_CP_ANSI => kernel32::ansi_code_page(),
        MB_CP_LOCALE => ctype::code_page(),
        page => page as u32,
    }
}

/// The DLL's process attach: the system's ANSI code page set.
pub fn initialize() {
    setmbcp(MB_CP_ANSI);
}

/// _setmbcp: the multibyte code page set (a code page, or _MB_CP_SBCS, _MB_CP_OEM, _MB_CP_ANSI or
/// _MB_CP_LOCALE): 0, or -1 for a code page that does not exist or that F2K has no tables for.
#[unsafe(export_name = "f2k_export__setmbcp")]
pub extern "C" fn setmbcp(page: i32) -> i32 {
    match classify(resolve(page)) {
        Page::SingleByte => {
            set_single_byte();
            0
        }
        Page::Multibyte => {
            // SAFETY: the call's one argument, an integer, as _setmbcp's kind reads it.
            unsafe {
                crate::stub::stubbed(
                    &crate::spec::_setmbcp,
                    "a double-byte code page's lead and trail bytes",
                    &[page as u32 as u64],
                )
            };
            -1
        }
        Page::Unknown => -1,
    }
}

/// _getmbcp: the multibyte code page, 0 for a single-byte one.
#[unsafe(export_name = "f2k_export__getmbcp")]
pub extern "C" fn getmbcp() -> i32 {
    CODE_PAGE.load(Relaxed)
}

/// _ismbblead: whether the low byte of `c` is a lead byte of the multibyte code page.
#[unsafe(export_name = "f2k_export__ismbblead")]
pub extern "C" fn ismbblead(c: u32) -> i32 {
    i32::from(MBCTYPE[usize::from(c as u8) + 1].load(Relaxed) & M1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::{DEBUG_PRINTS, LAST_ERROR};
    use crate::thread::{errno, set_errno};

    /// The lead bytes _ismbblead takes, counted.
    fn lead_bytes() -> usize {
        (0..256).filter(|&c| ismbblead(c) != 0).count()
    }

    /// msvcrt's mbblead block: every single-byte code page leaves no lead byte and _getmbcp 0; a
    /// code page that does not exist answers -1, errno untouched.
    #[test]
    fn single_byte_code_pages_as_captured() {
        for page in [
            1252,
            437,
            850,
            MB_CP_SBCS,
            MB_CP_OEM,
            MB_CP_ANSI,
            MB_CP_LOCALE,
        ] {
            set_errno(0);
            assert_eq!((setmbcp(page), errno(), getmbcp()), (0, 0, 0), "{page}");
            assert_eq!(lead_bytes(), 0);
        }
        for c in [
            0x41,
            0x80,
            0x81,
            0x9F,
            0xA0,
            0xE0,
            0xE9,
            0xFC,
            0xFF,
            0x181,
            0xFFFF_FF81,
        ] {
            assert_eq!(ismbblead(c), 0);
        }
        set_errno(0);
        assert_eq!((setmbcp(12345), errno(), getmbcp()), (-1, 0, 0));
        assert!(DEBUG_PRINTS.with(|prints| prints.borrow().is_empty()));
    }

    /// A double-byte code page F2K has no tables for logs and answers -1.
    #[test]
    fn a_double_byte_code_page_logs() {
        assert_eq!(setmbcp(932), -1);
        assert_eq!(getmbcp(), 0);
        assert_eq!(LAST_ERROR.with(|error| error.get()), 120);
        let printed = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
        assert_eq!(
            printed,
            ["stub msvcrt._setmbcp(codepage=932): a double-byte code page's lead and trail bytes\n"]
        );
    }
}
