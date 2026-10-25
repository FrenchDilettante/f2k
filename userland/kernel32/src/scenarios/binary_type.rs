//! The binary type group: GetBinaryTypeA and GetBinaryTypeW over the stand-in file and image
//! section services. The spawn fixture's binarytype block is the contract on the machine (where
//! the kernel's section creation refuses the files that are no images); these pin what kernel32
//! itself decides — the file opened as CreateProcess opens an image, the image section made of it
//! and its description asked, the type each description or refusal gives, the errors, the type
//! written only on success, and the file and section closed on every path.

use super::last_error;
use crate::binary_type::{get_binary_type_a, get_binary_type_w};
use crate::nt::children::{self, fail, SECTION_IMAGE};
use crate::nt::files::{calls, Call, CURRENT_DIRECTORY};
use crate::nt::host::{CLOSED, FAIL_NEXT, HANDLE, LAST_SECTION};

/// The last error a call leaves alone, armed before it.
const UNTOUCHED: u32 = 0x0F2F_2F2F;
/// The type slot as the call found it.
const UNWRITTEN: u32 = 0xF2F2_F2F2;

/// The section's refusals the scenarios arrange (ntstatus.h).
const STATUS_INVALID_IMAGE_NOT_MZ: u32 = 0xC000_012F;
const STATUS_MAPPED_FILE_SIZE_ZERO: u32 = 0xC000_011E;
const STATUS_INVALID_IMAGE_PROTECT: u32 = 0xC000_0130;
const STATUS_INVALID_IMAGE_WIN_16: u32 = 0xC000_0131;

/// A fresh scene: a console program's section, the stand-in process in `C:\CORPUS\`, nothing
/// recorded, the last error armed.
fn setup() {
    children::reset();
    CURRENT_DIRECTORY
        .with(|current| *current.borrow_mut() = "C:\\CORPUS\\".encode_utf16().collect());
    calls();
    CLOSED.with(|closed| closed.borrow_mut().clear());
    LAST_SECTION.with(|section| section.set(None));
    crate::base::set_last_error(UNTOUCHED);
}

fn closed() -> Vec<u32> {
    CLOSED.with(|closed| std::mem::take(&mut *closed.borrow_mut()))
}

/// GetBinaryTypeW and GetBinaryTypeA of `name`, each in a fresh scene with `arrange` run first:
/// their answers, the type slot and the last error (the two the same), and the handles closed.
fn both(name: &str, arrange: impl Fn()) -> (u32, u32, u32, Vec<u32>) {
    setup();
    arrange();
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut kind = UNWRITTEN;
    // SAFETY: a terminated name and a writable slot.
    let answer = unsafe { get_binary_type_w(wide.as_ptr(), &mut kind) };
    let wide_answer = (answer, kind, last_error(), closed());

    setup();
    arrange();
    let narrow: Vec<u8> = name.bytes().chain([0]).collect();
    let mut kind = UNWRITTEN;
    // SAFETY: as above.
    let answer = unsafe { get_binary_type_a(narrow.as_ptr(), &mut kind) };
    assert_eq!(
        (answer, kind, last_error(), closed()),
        wide_answer,
        "GetBinaryTypeA as GetBinaryTypeW"
    );
    wide_answer
}

/// The name the file was opened by, with the open's access, share and options.
fn opened() -> (u32, u32, u32, String) {
    match calls()
        .into_iter()
        .find(|call| matches!(call, Call::Open { .. }))
    {
        Some(Call::Open {
            access,
            share,
            options,
            name,
            ..
        }) => (access, share, options, name),
        other => panic!("no open: {other:?}"),
    }
}

/// A program: the file opened as CreateProcess opens an image (for execution, synchronizable,
/// shared for reading and deleting, synchronous, no directory) by the name as given (no `.exe`
/// added), an image section made of it (SECTION_ALL_ACCESS, PAGE_EXECUTE, SEC_IMAGE) and its
/// description asked; SCS_32BIT_BINARY written, the last error untouched, the file and the
/// section closed.
///
/// Pins: kernel32.GetBinaryTypeA, kernel32.GetBinaryTypeW
#[test]
fn a_program_is_a_32_bit_binary() {
    setup();
    let name: Vec<u16> = "spawnkid".encode_utf16().chain([0]).collect();
    let mut kind = UNWRITTEN;
    // SAFETY: a terminated name and a writable slot.
    let answer = unsafe { get_binary_type_w(name.as_ptr(), &mut kind) };
    assert_eq!((answer, kind, last_error()), (1, 0, UNTOUCHED));
    let (access, share, options, opened_name) = opened();
    assert_eq!((access, share, options), (0x0010_0020, 0x5, 0x60));
    assert_eq!(
        opened_name, "spawnkid",
        "against the current directory, no .exe added"
    );
    LAST_SECTION.with(|section| {
        assert_eq!(
            section.get(),
            Some((0x000F_001F, 0x10, 0x0100_0000, HANDLE, None))
        )
    });
    assert_eq!(closed(), [HANDLE, HANDLE], "the file and the section");

    assert_eq!(
        both("spawnkid.exe", || {}),
        (1, 0, UNTOUCHED, vec![HANDLE, HANDLE])
    );
}

/// spawn's binarytype block, as the section decides it: a DLL ERROR_BAD_EXE_FORMAT (its
/// description refuses it); a text file named `.txt` ERROR_BAD_EXE_FORMAT and one named `.exe`
/// SCS_DOS_BINARY (the section finds no MZ); an empty file ERROR_BAD_EXE_FORMAT. The type is
/// written only on success, which leaves the last error alone; the file is closed, and the
/// section when one was made.
///
/// Pins: kernel32.GetBinaryTypeA, kernel32.GetBinaryTypeW
#[test]
fn the_captured_files_are_typed_as_captured() {
    let dll = || SECTION_IMAGE.with(|words| *words.borrow_mut() = children::image(0x210E, 2));
    assert_eq!(
        both("C:\\WINNT\\system32\\kernel32.dll", dll),
        (0, UNWRITTEN, 193, vec![HANDLE, HANDLE])
    );
    let not_mz = || fail("NtCreateSection", STATUS_INVALID_IMAGE_NOT_MZ);
    assert_eq!(
        both("SCRATCH\\notexe.txt", not_mz),
        (0, UNWRITTEN, 193, vec![HANDLE])
    );
    assert_eq!(
        both("SCRATCH\\notexe.exe", not_mz),
        (1, 1, UNTOUCHED, vec![HANDLE])
    );
    let empty = || fail("NtCreateSection", STATUS_MAPPED_FILE_SIZE_ZERO);
    assert_eq!(
        both("SCRATCH\\empty.txt", empty),
        (0, UNWRITTEN, 193, vec![HANDLE])
    );
}

/// What cannot be opened, with Windows 2000's errors: a directory ERROR_ACCESS_DENIED (the open
/// refuses it), a missing file ERROR_FILE_NOT_FOUND, a file in a missing directory
/// ERROR_PATH_NOT_FOUND; no section is made, nothing is closed.
///
/// Pins: kernel32.GetBinaryTypeA, kernel32.GetBinaryTypeW
#[test]
fn what_cannot_be_opened_fails_as_on_windows_2000() {
    for (name, status, error) in [
        ("SCRATCH\\sub", 0xC000_00BA, 5),
        ("SCRATCH\\missing.exe", 0xC000_0034, 2),
        ("SCRATCH\\nodir\\missing.exe", 0xC000_003A, 3),
    ] {
        let refused = || FAIL_NEXT.with(|next| next.set(status));
        assert_eq!(both(name, refused), (0, UNWRITTEN, error, vec![]), "{name}");
        assert_eq!(LAST_SECTION.with(|section| section.get()), None, "{name}");
    }
}

/// The section's other answers: a DOS program (an MZ file without a new header) SCS_DOS_BINARY
/// and a Windows 3.x one SCS_WOW_BINARY whatever their names; a POSIX program SCS_POSIX_BINARY;
/// a failed description query its status's error, the file and the section closed. A null type
/// slot is left alone.
///
/// Pins: kernel32.GetBinaryTypeA, kernel32.GetBinaryTypeW
#[test]
fn the_section_types_other_programs() {
    let dos = || fail("NtCreateSection", STATUS_INVALID_IMAGE_PROTECT);
    assert_eq!(both("a.txt", dos), (1, 1, UNTOUCHED, vec![HANDLE]));
    let win16 = || fail("NtCreateSection", STATUS_INVALID_IMAGE_WIN_16);
    assert_eq!(both("a.dat", win16), (1, 2, UNTOUCHED, vec![HANDLE]));
    let posix = || SECTION_IMAGE.with(|words| *words.borrow_mut() = children::image(0x0103, 7));
    assert_eq!(
        both("a.exe", posix),
        (1, 4, UNTOUCHED, vec![HANDLE, HANDLE])
    );
    let unqueried = || fail("NtQuerySection", 0xC000_0022);
    assert_eq!(
        both("a.exe", unqueried),
        (0, UNWRITTEN, 5, vec![HANDLE, HANDLE])
    );

    setup();
    let name: Vec<u16> = "a.exe".encode_utf16().chain([0]).collect();
    // SAFETY: a terminated name; no slot.
    let answer = unsafe { get_binary_type_w(name.as_ptr(), core::ptr::null_mut()) };
    assert_eq!((answer, last_error()), (1, UNTOUCHED));
}
