//! The global atoms: GlobalAddAtom, GlobalFindAtom and GlobalGetAtomName, W and A, and
//! GlobalDeleteAtom, Win32 code over the window station's global atom table, which ntdll's atom
//! services reach (NtAddAtom, NtFindAtom, NtDeleteAtom, NtQueryInformationAtom), as Windows 2000's
//! kernel32 makes them. The table's rules are the kernel's (`kernel/src/atom.rs`): a name of '#'
//! and decimal digits is an integer atom's, any other a string atom's, matched in either ASCII
//! case, counted by each add and given back by each delete.
//!
//! A name whose pointer's high word is zero is an integer atom given as a number (MAKEINTATOM),
//! which never reaches the table: 0 (MAKEINTATOM(0) is NULL) answers 0 with no error, a value from
//! 0xC000 is ERROR_INVALID_PARAMETER, any other is the atom. A failed service's status becomes the
//! last error through ntdll's mapping: ERROR_FILE_NOT_FOUND for a name the table does not hold,
//! ERROR_INVALID_NAME for the empty one, ERROR_INVALID_PARAMETER for one past 255 characters or an
//! integer atom out of range, ERROR_INVALID_HANDLE for a string atom that is gone.
//!
//! An A call's name is converted through the ANSI code page into kernel32's own buffer first (one
//! past the longest name is refused with ERROR_INVALID_PARAMETER, as the table would refuse it),
//! and GlobalGetAtomNameA narrows the name back the way ntdll's RtlUnicodeStringToAnsiString does:
//! a buffer too short for the name and its terminator takes what fits, terminated, and the call
//! answers 0 with ERROR_MORE_DATA (the atom fixture's capture).

use crate::edge::{InStr, InWStr, OutBuf};
use crate::error::{
    answer,
    Failure,
    ERROR_INVALID_PARAMETER,
    ERROR_MORE_DATA,
    ERROR_NOT_ENOUGH_MEMORY,
};
use crate::ntcall::{self, MAX_ATOM_NAME};

/// The first string atom (MAXINTATOM): every integer atom is below it.
const FIRST_STRING_ATOM: u16 = 0xC000;

/// A failed service's status, as the last error it maps to.
fn status(status: ntcall::NtStatus) -> Failure {
    Failure::Status(status)
}

/// An integer atom given as a number: 0 for 0 (no atom, no error), the atom below 0xC000;
/// ERROR_INVALID_PARAMETER from there.
fn integer_atom(value: u16) -> Result<u16, Failure> {
    if value >= FIRST_STRING_ATOM {
        return Err(Failure::Error(ERROR_INVALID_PARAMETER));
    }
    Ok(value)
}

/// Whether a name argument is an integer atom given as a number: its high word zero.
fn is_integer(name: usize) -> bool {
    name >> 16 == 0
}

/// A W call's name: the integer atom, or the service's answer for the caller's string.
///
/// # Safety
///
/// A name whose high word is not zero points at a NUL-terminated string.
unsafe fn wide_name(
    name: *const u16,
    service: fn(&[u16]) -> Result<u16, ntcall::NtStatus>,
) -> Result<u16, Failure> {
    if is_integer(name as usize) {
        return integer_atom(name as u16);
    }
    // SAFETY: the caller's string (the contract).
    let name = unsafe { InWStr::new(name) };
    let units = crate::edge::wide_units(&name).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
    service(&units).map_err(status)
}

/// An A call's name: the integer atom, or the service's answer for the caller's string converted
/// through the ANSI code page.
///
/// # Safety
///
/// As [`wide_name`]'s, of bytes.
unsafe fn narrow_name(
    name: *const u8,
    service: fn(&[u16]) -> Result<u16, ntcall::NtStatus>,
) -> Result<u16, Failure> {
    if is_integer(name as usize) {
        return integer_atom(name as u16);
    }
    // SAFETY: the caller's string (the contract).
    let name = unsafe { InStr::new(name) };
    let mut units = [0u16; MAX_ATOM_NAME + 2];
    let length = crate::edge::ansi_into(Some(&name), &mut units)
        .ok_or(Failure::Error(ERROR_INVALID_PARAMETER))?;
    service(&units[..length]).map_err(status)
}

/// GlobalAddAtomW: the atom of the name, added to the global table (a string atom's reference
/// counted); 0 with the last error set when it cannot be.
///
/// # Safety
///
/// `name` is a NUL-terminated string, or an integer atom in its low word.
#[unsafe(export_name = "f2k_export_GlobalAddAtomW")]
pub unsafe extern "system" fn global_add_atom_w(name: *const u16) -> u16 {
    // SAFETY: the caller's name (the contract).
    answer(unsafe { wide_name(name, ntcall::add_atom) }, 0)
}

/// GlobalAddAtomA: GlobalAddAtomW over the name converted through the ANSI code page.
///
/// # Safety
///
/// As GlobalAddAtomW's, of bytes.
#[unsafe(export_name = "f2k_export_GlobalAddAtomA")]
pub unsafe extern "system" fn global_add_atom_a(name: *const u8) -> u16 {
    // SAFETY: the caller's name (the contract).
    answer(unsafe { narrow_name(name, ntcall::add_atom) }, 0)
}

/// GlobalFindAtomW: the atom the name has in the global table, its reference count untouched; 0
/// with ERROR_FILE_NOT_FOUND for a name it does not hold.
///
/// # Safety
///
/// As GlobalAddAtomW's.
#[unsafe(export_name = "f2k_export_GlobalFindAtomW")]
pub unsafe extern "system" fn global_find_atom_w(name: *const u16) -> u16 {
    // SAFETY: the caller's name (the contract).
    answer(unsafe { wide_name(name, ntcall::find_atom) }, 0)
}

/// GlobalFindAtomA: GlobalFindAtomW over the name converted through the ANSI code page.
///
/// # Safety
///
/// As GlobalAddAtomA's.
#[unsafe(export_name = "f2k_export_GlobalFindAtomA")]
pub unsafe extern "system" fn global_find_atom_a(name: *const u8) -> u16 {
    // SAFETY: the caller's name (the contract).
    answer(unsafe { narrow_name(name, ntcall::find_atom) }, 0)
}

/// GlobalDeleteAtom: one reference to a string atom given back, the atom gone with the last; an
/// integer atom (0 included) is left as it is. It answers 0 whether or not the atom was deleted,
/// the last error ERROR_INVALID_HANDLE for a string atom that is gone (the atom fixture's capture:
/// not the atom itself, as the documentation has it).
#[unsafe(export_name = "f2k_export_GlobalDeleteAtom")]
pub extern "system" fn global_delete_atom(atom: u16) -> u16 {
    if atom >= FIRST_STRING_ATOM {
        answer(ntcall::delete_atom(atom).map_err(status), ());
    }
    0
}

/// An atom's whole name, from the global table: "#" and its value for an integer atom.
fn atom_name(atom: u16) -> Result<ntcall::AtomBasicInformation, Failure> {
    ntcall::query_atom(atom).map_err(status)
}

/// GlobalGetAtomNameW: the atom's name into the buffer, as much of it as `size` characters hold,
/// terminated when there is room; the characters written. A size of 0 (or below) is 0 with
/// ERROR_MORE_DATA; the atom's own failures as the table answers them (ERROR_INVALID_PARAMETER for
/// atom 0, ERROR_INVALID_HANDLE for a string atom that is gone).
///
/// # Safety
///
/// `buffer` holds `size` characters.
#[unsafe(export_name = "f2k_export_GlobalGetAtomNameW")]
pub unsafe extern "system" fn global_get_atom_name_w(
    atom: u16,
    buffer: *mut u16,
    size: i32,
) -> u32 {
    // SAFETY: the caller's buffer of `size` characters (the contract; a size below 1 holds none).
    let buffer = unsafe { OutBuf::new(buffer, size.max(0) as usize) };
    answer(name_wide(atom, buffer), 0)
}

/// GlobalGetAtomNameW's work.
fn name_wide(atom: u16, mut buffer: OutBuf<'_, u16>) -> Result<u32, Failure> {
    let information = atom_name(atom)?;
    if buffer.is_empty() {
        return Err(Failure::Error(ERROR_MORE_DATA));
    }
    let name = information.name();
    let copied = name.len().min(buffer.len());
    buffer.put(&name[..copied]);
    if copied < buffer.len() {
        buffer.set(copied, 0);
    }
    Ok(copied as u32)
}

/// GlobalGetAtomNameA: the atom's name narrowed through the ANSI code page into the buffer, its
/// length; 0 with ERROR_MORE_DATA when it and its terminator do not fit in `size` bytes, what fits
/// written and terminated all the same. The atom's failures as GlobalGetAtomNameW's.
///
/// # Safety
///
/// `buffer` holds `size` bytes.
#[unsafe(export_name = "f2k_export_GlobalGetAtomNameA")]
pub unsafe extern "system" fn global_get_atom_name_a(atom: u16, buffer: *mut u8, size: i32) -> u32 {
    // SAFETY: the caller's buffer of `size` bytes (the contract; a size below 1 holds none).
    let buffer = unsafe { OutBuf::new(buffer, size.max(0) as usize) };
    answer(name_narrow(atom, buffer), 0)
}

/// GlobalGetAtomNameA's work.
fn name_narrow(atom: u16, mut buffer: OutBuf<'_, u8>) -> Result<u32, Failure> {
    let information = atom_name(atom)?;
    match ntcall::unicode_string_to_ansi_checked(&mut buffer, information.name()) {
        Ok(length) => Ok(length as u32),
        Err(_) => Err(Failure::Error(ERROR_MORE_DATA)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::last_error;

    fn wide(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    fn add_w(text: &str) -> u16 {
        // SAFETY: a terminated string of the test's.
        unsafe { global_add_atom_w(wide(text).as_ptr()) }
    }

    fn find_a(text: &[u8]) -> u16 {
        let mut name = text.to_vec();
        name.push(0);
        // SAFETY: as above.
        unsafe { global_find_atom_a(name.as_ptr()) }
    }

    /// An atom found in another case through the A call; the name back in either form; deleted
    /// after its references, then ERROR_INVALID_HANDLE with 0 answered.
    #[test]
    fn add_find_name_delete() {
        let atom = add_w("F2KAtomFixtureOne");
        assert!(atom >= FIRST_STRING_ATOM);
        assert_eq!(add_w("F2KATOMFIXTUREONE"), atom);
        assert_eq!(find_a(b"f2katomfixtureone"), atom);
        let mut name = [0xBEEFu16; 64];
        // SAFETY: the test's buffer of 64 characters.
        let length = unsafe { global_get_atom_name_w(atom, name.as_mut_ptr(), 64) };
        assert_eq!(length, 17);
        assert_eq!(&name[..18], &wide("F2KAtomFixtureOne")[..]);
        let mut narrow = [0x7Eu8; 64];
        // SAFETY: as above, in bytes.
        let length = unsafe { global_get_atom_name_a(atom, narrow.as_mut_ptr(), 64) };
        assert_eq!((length, &narrow[..18]), (17, &b"F2KAtomFixtureOne\0"[..]));
        assert_eq!(global_delete_atom(atom), 0);
        assert_eq!(global_delete_atom(atom), 0);
        crate::base::set_last_error(0);
        assert_eq!(global_delete_atom(atom), 0);
        assert_eq!(last_error(), 6);
        assert_eq!(find_a(b"F2KAtomFixtureOne"), 0);
        assert_eq!(last_error(), 2);
    }

    /// MAKEINTATOM: answered without the table; NULL is 0 with no error.
    #[test]
    fn integer_atoms_as_numbers() {
        // SAFETY: integer atoms in a pointer's low word: nothing is read.
        unsafe {
            assert_eq!(global_add_atom_w(123 as *const u16), 123);
            assert_eq!(global_find_atom_a(456 as *const u8), 456);
            crate::base::set_last_error(0);
            assert_eq!(global_add_atom_w(core::ptr::null()), 0);
            assert_eq!(last_error(), 0);
            assert_eq!(global_add_atom_a(0xC000 as *const u8), 0);
        }
        assert_eq!(last_error(), 87);
        assert_eq!(global_delete_atom(123), 0);
    }

    /// The short buffers: W fills what fits, unterminated, and answers it; A answers 0 with
    /// ERROR_MORE_DATA, what fits terminated.
    #[test]
    fn short_buffers() {
        let mut name = [0xBEEFu16; 8];
        // SAFETY: the test's buffer, longer than the sizes given.
        unsafe {
            assert_eq!(global_get_atom_name_w(123, name.as_mut_ptr(), 3), 3);
            assert_eq!(name[..4], [0x23, 0x31, 0x32, 0xBEEF]);
            assert_eq!(global_get_atom_name_w(123, name.as_mut_ptr(), 0), 0);
        }
        assert_eq!(last_error(), ERROR_MORE_DATA);
        let mut narrow = [0x7Eu8; 8];
        // SAFETY: as above, in bytes.
        unsafe {
            assert_eq!(global_get_atom_name_a(123, narrow.as_mut_ptr(), 3), 0);
        }
        assert_eq!(last_error(), ERROR_MORE_DATA);
        assert_eq!(&narrow[..4], b"#1\0~");
        // SAFETY: as above.
        unsafe {
            assert_eq!(global_get_atom_name_w(0, name.as_mut_ptr(), 8), 0);
        }
        assert_eq!(last_error(), 87);
    }
}
