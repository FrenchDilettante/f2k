//! The host tests' stand-ins for kernel32's global atoms (a table of names and reference counts,
//! with kernel32's errors) and win32k's property services (each window's properties a list of
//! its record's), and the enumeration callbacks the tests register.

use std::cell::RefCell;
use std::vec::Vec;

use rtl::status::*;
use rtl::window::PropSet;
// ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME and ERROR_INVALID_PARAMETER, kernel32's atom
// errors.
use rtl::winerror::{ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME, ERROR_INVALID_PARAMETER};

use super::{wm, LAST_ERROR};

/// The first string atom.
const FIRST_STRING_ATOM: u16 = 0xC000;

std::thread_local! {
    /// The global atom table: each string atom's name (upper-cased) and reference count, the atom
    /// its index from FIRST_STRING_ATOM (a deleted one's slot left empty).
    pub static ATOMS: RefCell<Vec<Option<(Vec<u16>, u32)>>> = const { RefCell::new(Vec::new()) };
    /// The WNDENUMPROCs the tests registered.
    static ENUM_PROCS: RefCell<Vec<EnumProc>> = const { RefCell::new(Vec::new()) };
}

/// A WNDENUMPROC, as the tests write one.
pub type EnumProc = fn(u32, u32) -> u32;

/// The first number a registered callback is named by.
const FIRST_ENUM_PROC: u32 = 0x0050_1000;

/// `proc` registered: the number that names it.
pub fn enum_procedure(proc: EnumProc) -> u32 {
    ENUM_PROCS.with(|procs| {
        procs.borrow_mut().push(proc);
        FIRST_ENUM_PROC + 4 * (procs.borrow().len() as u32 - 1)
    })
}

/// The WNDENUMPROC `proc` names, called.
pub unsafe fn call_window_enum_procedure(proc: u32, window: u32, lparam: u32) -> u32 {
    let proc = ENUM_PROCS.with(|procs| procs.borrow()[((proc - FIRST_ENUM_PROC) / 4) as usize]);
    proc(window, lparam)
}

/// A name's lookup: an integer atom (MAKEINTATOM, or "#" and decimal digits), or a string's units
/// upper-cased; the error kernel32 answers for a name it refuses.
fn atom_name(units: Vec<u16>) -> Result<Result<u16, Vec<u16>>, u32> {
    if units.is_empty() {
        return Err(ERROR_INVALID_NAME);
    }
    if units.len() > 255 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    if units[0] == u16::from(b'#') && units.len() > 1 {
        let digits = std::string::String::from_utf16_lossy(&units[1..]);
        if let Ok(value) = digits.parse::<u16>() {
            return Ok(Ok(value));
        }
    }
    Ok(Err(units
        .iter()
        .map(|&u| rtl::text::atom_upcase(u))
        .collect()))
}

/// The units of the name at `name`, wide or narrow, read to its NUL.
fn units_at(name: usize, wide: bool) -> Vec<u16> {
    if wide {
        // SAFETY: the caller's NUL-terminated name.
        unsafe { rtl::cstr::units_until_nul(name as *const u16) }.to_vec()
    } else {
        // SAFETY: as above, of bytes (ASCII in the tests).
        unsafe { core::ffi::CStr::from_ptr(name as *const core::ffi::c_char) }
            .to_bytes()
            .iter()
            .map(|&b| u16::from(b))
            .collect()
    }
}

fn fail(error: u32) -> u16 {
    LAST_ERROR.with(|e| e.set(error));
    0
}

fn add_atom(name: usize, wide: bool) -> u16 {
    if name >> 16 == 0 {
        return name as u16;
    }
    match atom_name(units_at(name, wide)) {
        Err(error) => fail(error),
        Ok(Ok(atom)) => atom,
        Ok(Err(units)) => ATOMS.with(|atoms| {
            let mut atoms = atoms.borrow_mut();
            if let Some(at) = atoms
                .iter()
                .position(|a| a.as_ref().is_some_and(|(n, _)| *n == units))
            {
                atoms[at].as_mut().unwrap().1 += 1;
                return FIRST_STRING_ATOM + at as u16;
            }
            atoms.push(Some((units, 1)));
            FIRST_STRING_ATOM + atoms.len() as u16 - 1
        }),
    }
}

fn find_atom(name: usize, wide: bool) -> u16 {
    if name >> 16 == 0 {
        return name as u16;
    }
    match atom_name(units_at(name, wide)) {
        Err(error) => fail(error),
        Ok(Ok(atom)) => atom,
        Ok(Err(units)) => ATOMS.with(|atoms| {
            atoms
                .borrow()
                .iter()
                .position(|a| a.as_ref().is_some_and(|(n, _)| *n == units))
                .map_or_else(
                    || fail(ERROR_FILE_NOT_FOUND),
                    |at| FIRST_STRING_ATOM + at as u16,
                )
        }),
    }
}

pub unsafe extern "system" fn GlobalAddAtomW(name: usize) -> u16 {
    add_atom(name, true)
}

pub unsafe extern "system" fn GlobalAddAtomA(name: usize) -> u16 {
    add_atom(name, false)
}

pub unsafe extern "system" fn GlobalFindAtomW(name: usize) -> u16 {
    find_atom(name, true)
}

pub unsafe extern "system" fn GlobalFindAtomA(name: usize) -> u16 {
    find_atom(name, false)
}

pub unsafe extern "system" fn GlobalDeleteAtom(atom: u16) -> u16 {
    if atom >= FIRST_STRING_ATOM {
        ATOMS.with(|atoms| {
            let mut atoms = atoms.borrow_mut();
            if let Some(slot) = atoms.get_mut((atom - FIRST_STRING_ATOM) as usize) {
                if let Some((_, count)) = slot {
                    *count -= 1;
                    if *count == 0 {
                        *slot = None;
                    }
                }
            }
        });
    }
    0
}

/// A string atom's reference count, 0 when the name has none (the tests' look at the table).
pub fn atom_references(name: &str) -> u32 {
    let units: Vec<u16> = name.to_uppercase().encode_utf16().collect();
    ATOMS.with(|atoms| {
        atoms
            .borrow()
            .iter()
            .flatten()
            .find(|(n, _)| *n == units)
            .map_or(0, |(_, count)| *count)
    })
}

pub unsafe extern "system" fn NtUserSetProp(window: usize, atom: u32, data: u32) -> u32 {
    wm(|wm| match wm.window(window) {
        Err(status) => status,
        Ok(_) if atom == 0 => STATUS_INVALID_PARAMETER,
        Ok(w) => {
            let atom = atom as u16;
            match w.props.iter_mut().find(|(a, _)| *a == atom) {
                Some(prop) => prop.1 = data,
                None => w.props.push((atom, data)),
            }
            STATUS_SUCCESS
        }
    })
}

pub unsafe extern "system" fn NtUserRemoveProp(window: usize, atom: u32, data: *mut u32) -> u32 {
    wm(|wm| match wm.window(window) {
        Err(status) => status,
        Ok(w) => {
            let at = w.props.iter().position(|&(a, _)| u32::from(a) == atom);
            let answer = at.map_or(0, |at| w.props.remove(at).1);
            // SAFETY: the caller's out-pointer.
            unsafe { data.write(answer) };
            STATUS_SUCCESS
        }
    })
}

pub unsafe extern "system" fn NtUserBuildPropList(
    window: usize,
    list: *mut PropSet,
    max: u32,
    count: *mut u32,
) -> u32 {
    wm(|wm| match wm.window(window) {
        Err(status) => status,
        Ok(w) => {
            for (index, &(atom, data)) in w.props.iter().take(max as usize).enumerate() {
                // SAFETY: the caller's list of `max` entries.
                unsafe {
                    list.add(index).write(PropSet {
                        data,
                        atom: u32::from(atom),
                    })
                };
            }
            // SAFETY: the caller's out-pointer.
            unsafe { count.write(w.props.len() as u32) };
            if w.props.len() > max as usize {
                STATUS_BUFFER_TOO_SMALL
            } else {
                STATUS_SUCCESS
            }
        }
    })
}
