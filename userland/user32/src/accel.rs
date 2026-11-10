//! Keyboard accelerators: LoadAcceleratorsW and LoadAcceleratorsA, CopyAcceleratorTableW and
//! CopyAcceleratorTableA, DestroyAcceleratorTable, TranslateAcceleratorW and TranslateAcceleratorA,
//! over win32k's accelerator services ([`imports`]).
//!
//! A table is a win32k object. LoadAccelerators reads an ACCELERATORS resource here, as Windows
//! 2000's user32 does (rtl::accel's ACCELTABLEENTRY: a character entry's key an ANSI character,
//! which becomes the table's UTF-16 unit), and has the kernel make the table, naming the resource
//! (its data's address): a resource loaded before answers the same table, until
//! DestroyAcceleratorTable has been called as often (the accel fixture's capture, and Windows'
//! documentation of DestroyAcceleratorTable's answer).
//!
//! TranslateAccelerator hands the message to win32k, which matches it against the table and sends
//! the window its WM_COMMAND (and WM_INITMENU and WM_INITMENUPOPUP when the window's menu holds the
//! command), queued for the window's thread: user32 receives them before it returns, so the window
//! procedure sees them during the call, as on Windows 2000. The A form converts a character
//! message's character from the ANSI code page first; CopyAcceleratorTableA converts a character
//! entry's key back.

use rtl::accel::{Accel, AccelTableEntry, FVIRTKEY, WM_CHAR, WM_SYSCHAR};
use rtl::edge::OutBuf;
use rtl::status::{NtStatus, STATUS_INVALID_HANDLE, STATUS_OBJECT_TYPE_MISMATCH};
use rtl::user::Msg;

use crate::imports::{self, ResourceName};
use crate::{failed_with, message};

/// RT_ACCELERATOR: an accelerator table's resource type.
const RT_ACCELERATOR: u16 = 9;

/// The most entries a table holds (the kernel's).
const MAX_ENTRIES: usize = 128;

/// ERROR_INVALID_ACCEL_HANDLE.
pub const ERROR_INVALID_ACCEL_HANDLE: u32 = 1403;

/// The Win32 error of a failed accelerator service: a handle naming no table is
/// ERROR_INVALID_ACCEL_HANDLE, a window naming nothing ERROR_INVALID_WINDOW_HANDLE (the kernel's
/// accelerator module), anything else what ntdll maps it to.
pub fn accel_error(status: NtStatus) -> u32 {
    match status.0 {
        STATUS_OBJECT_TYPE_MISMATCH => ERROR_INVALID_ACCEL_HANDLE,
        STATUS_INVALID_HANDLE => crate::ERROR_INVALID_WINDOW_HANDLE,
        _ => imports::dos_error(status),
    }
}

/// The UTF-16 unit of an ANSI character (the ANSI code page's, through ntdll).
fn wide_of(byte: u8) -> u16 {
    let mut unit = [0u16; 1];
    imports::multi_byte_to_unicode(&mut unit, &[byte]);
    unit[0]
}

/// The ANSI character of a UTF-16 unit (the ANSI code page's, through ntdll).
fn narrow_of(unit: u16) -> u16 {
    let mut byte = [0u8; 1];
    imports::unicode_to_multi_byte(&mut byte, &[unit]);
    u16::from(byte[0])
}

// --- LoadAccelerators
// ------------------------------------------------------------------------------

/// LoadAcceleratorsW: the table the module's ACCELERATORS resource `name` describes (NULL: the
/// program's module), the same one for every load until destroyed as often; NULL with the last
/// error when the module has no such resource.
///
/// # Safety
///
/// `name` is a resource number (its high word zero) or the address of a NUL-terminated UTF-16
/// string, as for the platform's.
#[unsafe(export_name = "f2k_export_LoadAcceleratorsW")]
pub unsafe extern "system" fn load_accelerators_w(instance: usize, name: *const u16) -> usize {
    // SAFETY: the caller's contract.
    unsafe { load_accelerators(instance, ResourceName::Wide(name as usize)) }
}

/// LoadAcceleratorsA: LoadAcceleratorsW's, the name an ANSI string or a number.
///
/// # Safety
///
/// As LoadAcceleratorsW's, the string ANSI.
#[unsafe(export_name = "f2k_export_LoadAcceleratorsA")]
pub unsafe extern "system" fn load_accelerators_a(instance: usize, name: *const u8) -> usize {
    // SAFETY: the caller's contract.
    unsafe { load_accelerators(instance, ResourceName::Narrow(name as usize)) }
}

/// LoadAccelerators's core: the resource found and read, its entries converted, the table made
/// (or the one loaded before answered).
///
/// # Safety
///
/// A string `name` is the caller's NUL-terminated string.
unsafe fn load_accelerators(instance: usize, name: ResourceName) -> usize {
    // SAFETY: the caller's contract.
    let Some(found) = (unsafe { imports::find_named_resource(instance, RT_ACCELERATOR, name) })
    else {
        return 0;
    };
    let Some(data) = imports::resource_data(instance, found) else {
        return 0;
    };
    let mut entries = [Accel::default(); MAX_ENTRIES];
    let mut count = 0;
    for (slot, entry) in entries.iter_mut().zip(AccelTableEntry::entries(data)) {
        let virt = (entry.flags & 0x7F) as u8;
        let key = if virt & FVIRTKEY == 0 && entry.ansi < 0x100 {
            wide_of(entry.ansi as u8)
        } else {
            entry.ansi
        };
        *slot = Accel {
            virt,
            pad: 0,
            key,
            cmd: entry.id,
        };
        count += 1;
    }
    failed_with(
        imports::create_accelerator_table(&entries[..count], instance, data.as_ptr() as usize),
        accel_error,
    )
    .unwrap_or(0)
}

// --- The table
// -------------------------------------------------------------------------------------

/// CopyAcceleratorTableW: with no buffer the table's entry count; else as many of its entries as
/// the buffer's `count` takes, their number. 0 with ERROR_INVALID_ACCEL_HANDLE for a handle naming
/// no table.
///
/// # Safety
///
/// `entries` is null or the caller's buffer of `count` ACCELs, as for the platform's.
#[unsafe(export_name = "f2k_export_CopyAcceleratorTableW")]
pub unsafe extern "system" fn copy_accelerator_table_w(
    table: usize,
    entries: *mut Accel,
    count: i32,
) -> i32 {
    // SAFETY: the caller's contract.
    let buffer = unsafe { OutBuf::optional(entries, count.max(0) as usize) };
    copy_table(table, buffer, |key| key)
}

/// CopyAcceleratorTableA: CopyAcceleratorTableW's, a character entry's key converted to the ANSI
/// code page.
///
/// # Safety
///
/// As CopyAcceleratorTableW's.
#[unsafe(export_name = "f2k_export_CopyAcceleratorTableA")]
pub unsafe extern "system" fn copy_accelerator_table_a(
    table: usize,
    entries: *mut Accel,
    count: i32,
) -> i32 {
    // SAFETY: the caller's contract.
    let buffer = unsafe { OutBuf::optional(entries, count.max(0) as usize) };
    copy_table(table, buffer, narrow_of)
}

/// CopyAcceleratorTable's core: the entries copied into a buffer of this DLL's, a character
/// entry's key through `key`, then into the caller's.
fn copy_table(table: usize, buffer: Option<OutBuf<'_, Accel>>, key: impl Fn(u16) -> u16) -> i32 {
    let Some(mut buffer) = buffer else {
        return failed_with(imports::copy_accelerator_table(table, None), accel_error)
            .map_or(0, |count| count as i32);
    };
    let mut local = [Accel::default(); MAX_ENTRIES];
    let room = buffer.len().min(MAX_ENTRIES);
    let Some(copied) = failed_with(
        imports::copy_accelerator_table(table, Some(&mut local[..room])),
        accel_error,
    ) else {
        return 0;
    };
    let copied = copied as usize;
    for entry in &mut local[..copied] {
        if entry.virt & FVIRTKEY == 0 {
            entry.key = key(entry.key);
        }
    }
    buffer.put(&local[..copied]);
    copied as i32
}

/// DestroyAcceleratorTable: the table's load count down, the table destroyed with its last load;
/// TRUE then, FALSE while loads remain, or with ERROR_INVALID_ACCEL_HANDLE for a handle naming no
/// table.
#[unsafe(export_name = "f2k_export_DestroyAcceleratorTable")]
pub extern "system" fn destroy_accelerator_table(table: usize) -> i32 {
    failed_with(imports::destroy_accelerator_table(table), accel_error)
        .is_some_and(|destroyed| destroyed) as i32
}

// --- TranslateAccelerator
// --------------------------------------------------------------------------

/// TranslateAcceleratorW: the message translated for the window through the table, the messages
/// it sent received; TRUE when it was an accelerator. 0 with ERROR_INVALID_ACCEL_HANDLE for a
/// handle naming no table; a null window translates nothing.
///
/// # Safety
///
/// `msg` is the caller's MSG, as for the platform's.
#[unsafe(export_name = "f2k_export_TranslateAcceleratorW")]
pub unsafe extern "system" fn translate_accelerator_w(
    window: usize,
    table: usize,
    msg: *const Msg,
) -> i32 {
    // SAFETY: the caller's contract: a MSG, read once (at any alignment).
    let msg = unsafe { msg.read_unaligned() };
    translate(window, table, &msg)
}

/// TranslateAcceleratorA: TranslateAcceleratorW's, a character message's character converted
/// from the ANSI code page first.
///
/// # Safety
///
/// As TranslateAcceleratorW's.
#[unsafe(export_name = "f2k_export_TranslateAcceleratorA")]
pub unsafe extern "system" fn translate_accelerator_a(
    window: usize,
    table: usize,
    msg: *const Msg,
) -> i32 {
    // SAFETY: the caller's contract: a MSG, read once (at any alignment).
    let mut msg = unsafe { msg.read_unaligned() };
    if matches!(msg.message, WM_CHAR | WM_SYSCHAR) && msg.wparam < 0x100 {
        msg.wparam = u32::from(wide_of(msg.wparam as u8));
    }
    translate(window, table, &msg)
}

/// TranslateAccelerator's core.
fn translate(window: usize, table: usize, msg: &Msg) -> i32 {
    match failed_with(
        imports::translate_accelerator(window, table, msg),
        accel_error,
    ) {
        Some(true) => {
            message::receive_sent();
            1
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::{add_resource, LAST_ERROR, PROGRAM, TRANSLATED};

    /// The accel fixture's table 300 (accel.rc), as the resource compiler writes it.
    fn table_300() -> std::vec::Vec<u8> {
        let mut data = std::vec::Vec::new();
        let entries: [(u16, u16, u16); 7] = [
            (0x00, 65, 301),
            (0x00, 3, 302),
            (0x01, 116, 303),
            (0x09, 90, 304),
            (0x11, 88, 305),
            (0x05, 46, 306),
            (0x83, 75, 307),
        ];
        for (flags, ansi, id) in entries {
            for word in [flags, ansi, id, 0] {
                data.extend_from_slice(&word.to_le_bytes());
            }
        }
        data
    }

    /// Loads of one resource share a table until destroyed as often; the entries copy back as the
    /// load section's capture shows them.
    ///
    /// Pins: user32.LoadAcceleratorsW, user32.LoadAcceleratorsA, user32.CopyAcceleratorTableW,
    /// user32.CopyAcceleratorTableA, user32.DestroyAcceleratorTable
    #[test]
    fn loads_share_a_table_and_copy_its_entries() {
        add_resource(PROGRAM, RT_ACCELERATOR, 300, &table_300());
        // SAFETY: resource numbers.
        let (w, a) = unsafe {
            (
                load_accelerators_w(0, 300 as *const u16),
                load_accelerators_a(0, 300 as *const u8),
            )
        };
        assert_ne!(w, 0);
        assert_eq!(a, w);
        // SAFETY: no buffer.
        assert_eq!(
            unsafe { copy_accelerator_table_w(w, core::ptr::null_mut(), 0) },
            7
        );
        let mut entries = [Accel {
            virt: 0xEE,
            pad: 0xEE,
            key: 0xEEEE,
            cmd: 0xEEEE,
        }; 16];
        // SAFETY: the test's buffer of 16.
        assert_eq!(
            unsafe { copy_accelerator_table_a(w, entries.as_mut_ptr(), 3) },
            3
        );
        assert_eq!(
            (entries[1].virt, entries[1].key, entries[1].cmd),
            (0, 3, 302)
        );
        assert_eq!(entries[3].key, 0xEEEE, "past the count: untouched");
        // SAFETY: as above.
        assert_eq!(
            unsafe { copy_accelerator_table_w(w, entries.as_mut_ptr(), 16) },
            7
        );
        assert_eq!(
            (entries[6].virt, entries[6].key),
            (0x03, 75),
            "the last flag dropped"
        );
        // SAFETY: no buffer.
        assert_eq!(
            unsafe { copy_accelerator_table_w(0, core::ptr::null_mut(), 0) },
            0
        );
        assert_eq!(LAST_ERROR.with(|e| e.get()), ERROR_INVALID_ACCEL_HANDLE);
        assert_eq!(destroy_accelerator_table(w), 0);
        assert_eq!(destroy_accelerator_table(w), 1);
        assert_eq!(destroy_accelerator_table(w), 0);
    }

    /// The A form converts a character message's character before the kernel sees it.
    ///
    /// Pins: user32.TranslateAcceleratorA, user32.TranslateAcceleratorW
    #[test]
    fn ansi_translations_convert_the_character() {
        add_resource(PROGRAM, RT_ACCELERATOR, 300, &table_300());
        // SAFETY: a resource number.
        let table = unsafe { load_accelerators_w(0, 300 as *const u16) };
        let msg = Msg {
            hwnd: 0,
            message: WM_CHAR,
            wparam: 0x80,
            ..Msg::default()
        };
        // SAFETY: the test's MSG.
        assert_eq!(unsafe { translate_accelerator_a(0, table, &msg) }, 0);
        let seen = TRANSLATED
            .with(|seen| seen.borrow().last().copied())
            .unwrap();
        assert_eq!(seen.wparam, 0x20AC, "cp1252's euro sign");
        // SAFETY: as above.
        assert_eq!(unsafe { translate_accelerator_w(0, 0, &msg) }, 0);
        assert_eq!(LAST_ERROR.with(|e| e.get()), ERROR_INVALID_ACCEL_HANDLE);
    }
}
