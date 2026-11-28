//! The atom services' stand-ins: a global atom table of the test's thread, the kernel's rules
//! (`kernel/src/atom.rs`) in miniature: '#' and decimal digits name an integer atom, from 1 to
//! 0xBFFF; a string atom (from 0xC000) is 1 to 255 units, matched in either ASCII case, and
//! counted.

use std::cell::RefCell;
use std::vec::Vec;

// STATUS_OBJECT_NAME_INVALID: an empty name.
use rtl::status::STATUS_OBJECT_NAME_INVALID;
use rtl::status::{
    STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_SUCCESS,
};

/// One string atom: its name and its references.
type Entry = Option<(Vec<u16>, u16)>;

std::thread_local! {
    /// The table: an entry per string atom, the atom 0xC000 and its index (none for a free
    /// one).
    pub static ATOMS: RefCell<Vec<Entry>> = const { RefCell::new(Vec::new()) };
}

/// The name `length` bytes at `name` give: an integer atom's value, or a string atom's
/// units; the status refusing it.
fn judge(name: *const u16, length: u32) -> Result<Result<u16, Vec<u16>>, u32> {
    let count = (length / 2) as usize;
    if count == 0 {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    if count > 255 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: the caller's name, `count` units.
    let units = unsafe { std::slice::from_raw_parts(name, count) }.to_vec();
    let digit = |unit: &u16| (0x30..=0x39).contains(unit);
    if units[0] == u16::from(b'#') && units[1..].iter().all(digit) {
        let value = units[1..].iter().fold(0u32, |value, &unit| {
            (value * 10 + u32::from(unit - 0x30)).min(0x1_0000)
        });
        return match value {
            1..0xC000 => Ok(Ok(value as u16)),
            _ => Err(STATUS_INVALID_PARAMETER),
        };
    }
    Ok(Err(units))
}

/// Whether two names match, as the atom tables match them.
fn same(a: &[u16], b: &[u16]) -> bool {
    rtl::text::same_atom_name(a.iter().copied(), b.iter().copied())
}

/// The index of the entry named `units`.
fn index_of(table: &[Entry], units: &[u16]) -> Option<usize> {
    table
        .iter()
        .position(|entry| entry.as_ref().is_some_and(|(name, _)| same(name, units)))
}

/// The atom written where asked: success.
fn put(atom: *mut u16, value: u16) -> u32 {
    if !atom.is_null() {
        // SAFETY: the caller's RTL_ATOM.
        unsafe { atom.write(value) };
    }
    STATUS_SUCCESS
}

pub unsafe extern "system" fn NtAddAtom(name: *const u16, length: u32, atom: *mut u16) -> u32 {
    let units = match judge(name, length) {
        Err(status) => return status,
        Ok(Ok(value)) => return put(atom, value),
        Ok(Err(units)) => units,
    };
    let index = ATOMS.with_borrow_mut(|table| {
        if let Some(index) = index_of(table, &units) {
            table[index].as_mut().expect("a live entry").1 += 1;
            return index;
        }
        match table.iter().position(Option::is_none) {
            Some(index) => {
                table[index] = Some((units, 1));
                index
            }
            None => {
                table.push(Some((units, 1)));
                table.len() - 1
            }
        }
    });
    put(atom, 0xC000 + index as u16)
}

pub unsafe extern "system" fn NtFindAtom(name: *const u16, length: u32, atom: *mut u16) -> u32 {
    match judge(name, length) {
        Err(status) => status,
        Ok(Ok(value)) => put(atom, value),
        Ok(Err(units)) => match ATOMS.with_borrow(|table| index_of(table, &units)) {
            Some(index) => put(atom, 0xC000 + index as u16),
            None => STATUS_OBJECT_NAME_NOT_FOUND,
        },
    }
}

pub unsafe extern "system" fn NtDeleteAtom(atom: u16) -> u32 {
    match atom {
        0 => STATUS_INVALID_PARAMETER,
        1..0xC000 => STATUS_SUCCESS,
        _ => ATOMS.with_borrow_mut(|table| {
            let Some(slot) = table.get_mut(usize::from(atom - 0xC000)) else {
                return STATUS_INVALID_HANDLE;
            };
            let Some((_, references)) = slot else {
                return STATUS_INVALID_HANDLE;
            };
            *references -= 1;
            if *references == 0 {
                *slot = None;
            }
            STATUS_SUCCESS
        }),
    }
}

/// AtomBasicInformation alone: an integer atom's name "#" and its value, a string atom's its
/// own; as much as fits, terminated when there is room.
pub unsafe extern "system" fn NtQueryInformationAtom(
    atom: u16,
    class: u32,
    information: *mut u8,
    length: u32,
    _returned: *mut u32,
) -> u32 {
    assert_eq!(class, 0, "the stand-in answers AtomBasicInformation alone");
    let name: Vec<u16> = match atom {
        0 => return STATUS_INVALID_PARAMETER,
        1..0xC000 => std::format!("#{atom}").encode_utf16().collect(),
        _ => {
            let entry =
                ATOMS.with_borrow(|table| table.get(usize::from(atom - 0xC000)).cloned().flatten());
            match entry {
                Some((name, _)) => name,
                None => return STATUS_INVALID_HANDLE,
            }
        }
    };
    let room = (length as usize - 6) / 2;
    let copied = name.len().min(room);
    // SAFETY: the caller's structure, `length` bytes.
    let out = unsafe { std::slice::from_raw_parts_mut(information, length as usize) };
    out[4..6].copy_from_slice(&((2 * copied) as u16).to_le_bytes());
    for (at, unit) in name[..copied].iter().chain(&[0]).take(room).enumerate() {
        out[6 + 2 * at..8 + 2 * at].copy_from_slice(&unit.to_le_bytes());
    }
    STATUS_SUCCESS
}
