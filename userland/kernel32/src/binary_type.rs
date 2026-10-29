//! GetBinaryTypeA and GetBinaryTypeW: what kind of program a file is, without running it.
//!
//! As Windows 2000's kernel32 decides it, through an image section: the file opened as
//! CreateProcess opens an image (for execution, a directory refused), an image section made of it
//! (NtCreateSection with SEC_IMAGE) and its SECTION_IMAGE_INFORMATION asked (NtQuerySection). A
//! Windows image's description decides between a program ([`of_image`]: SCS_32BIT_BINARY, or
//! SCS_POSIX_BINARY by its subsystem) and an image that is none (a DLL); the section's refusal of a
//! file that is no Windows image says what it is instead ([`of_refusal`]: a DOS or Windows 3.x
//! program, or a file without the MZ signature, typed by its name's extension). The file and the
//! section are closed on every path.
//!
//! As spawn's capture pins it: a Windows program is SCS_32BIT_BINARY; a DLL, a text file named
//! `.txt` and an empty file are ERROR_BAD_EXE_FORMAT; a file that is not an image but is named
//! `.exe` is SCS_DOS_BINARY (the DOS machine would run it); the name is taken as given (no `.exe`
//! added); a directory is ERROR_ACCESS_DENIED, a missing file ERROR_FILE_NOT_FOUND, a missing
//! directory ERROR_PATH_NOT_FOUND. The type is written only on success, and success leaves the
//! last error alone. Its binaryforms block, on made-up headers: an NE program for OS/2 is a DOS
//! program (SCS_DOS_BINARY), not SCS_OS216_BINARY, which Windows 2000's GetBinaryType does not
//! answer for it; a DOS program named `.txt` is one all the same (the name types only a file
//! without MZ).

use crate::create::{OPEN_ACCESS, OPEN_OPTIONS, OPEN_SHARE};
use crate::edge::{InStr, InWStr, Out};
use crate::error::{bool_answer, Failure};
use crate::files::{self, NtPath, Wide, ERROR_PATH_NOT_FOUND};
use crate::heap::Owned;
use crate::ntcall::{self, NtStatus, SectionImageInformation};

/// The binary types (winbase.h's SCS_*).
pub const SCS_32BIT_BINARY: u32 = 0;
pub const SCS_DOS_BINARY: u32 = 1;
pub const SCS_WOW_BINARY: u32 = 2;
pub const SCS_PIF_BINARY: u32 = 3;
pub const SCS_POSIX_BINARY: u32 = 4;
pub const SCS_OS216_BINARY: u32 = 5;

pub const ERROR_BAD_EXE_FORMAT: u32 = 193;

/// What an image's description says (its file header's characteristics, its machine, its
/// subsystem): an executable, a DLL, an i386 image, the POSIX subsystem.
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const IMAGE_SUBSYSTEM_POSIX_CUI: u32 = 7;

/// The image section's refusals of a file that is no Windows image (ntstatus.h): a file no image
/// section can be made of, a broken or foreign PE file, an empty file; an OS/2 (NE) program, an LE
/// one, a file without the MZ signature, a DOS program (an MZ file without a new header), a
/// Windows 3.x program.
const STATUS_INVALID_FILE_FOR_SECTION: NtStatus = 0xC000_0020;
const STATUS_INVALID_IMAGE_FORMAT: NtStatus = 0xC000_007B;
const STATUS_MAPPED_FILE_SIZE_ZERO: NtStatus = 0xC000_011E;
const STATUS_INVALID_IMAGE_NE_FORMAT: NtStatus = 0xC000_011B;
const STATUS_INVALID_IMAGE_LE_FORMAT: NtStatus = 0xC000_012E;
const STATUS_INVALID_IMAGE_NOT_MZ: NtStatus = 0xC000_012F;
const STATUS_INVALID_IMAGE_PROTECT: NtStatus = 0xC000_0130;
const STATUS_INVALID_IMAGE_WIN_16: NtStatus = 0xC000_0131;

/// A file that is no program of a type GetBinaryType names.
const BAD: Failure = Failure::Error(ERROR_BAD_EXE_FORMAT);

/// The type a name's extension gives a file that is not an image (the DOS machine runs a `.com` or
/// `.exe` as a DOS program, a `.pif` describes one); none for any other name.
fn by_extension(name: &[u16]) -> Option<u32> {
    let file_name = name
        .iter()
        .rposition(|&unit| unit == b'\\' as u16 || unit == b'/' as u16)
        .map_or(name, |at| &name[at + 1..]);
    let extension = &file_name[file_name.iter().rposition(|&unit| unit == b'.' as u16)? + 1..];
    let is = |wanted: &[u8]| {
        extension.len() == wanted.len()
            && extension
                .iter()
                .zip(wanted)
                .all(|(&unit, &byte)| unit < 0x80 && (unit as u8).eq_ignore_ascii_case(&byte))
    };
    if is(b"exe") || is(b"com") {
        Some(SCS_DOS_BINARY)
    } else if is(b"pif") {
        Some(SCS_PIF_BINARY)
    } else {
        None
    }
}

/// What an image section's description says the file is: an executable for the i386 is a Windows
/// program (SCS_32BIT_BINARY), or a POSIX one by its subsystem; a DLL, an image not marked
/// executable or one for another machine is ERROR_BAD_EXE_FORMAT.
pub fn of_image(image: &SectionImageInformation) -> Result<u32, Failure> {
    let characteristics = image.image_characteristics;
    if characteristics & IMAGE_FILE_DLL != 0
        || characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0
        || image.machine != IMAGE_FILE_MACHINE_I386
    {
        return Err(BAD);
    }
    Ok(if image.subsystem_type == IMAGE_SUBSYSTEM_POSIX_CUI {
        SCS_POSIX_BINARY
    } else {
        SCS_32BIT_BINARY
    })
}

/// What the image section's refusal `status` says the file named `name` (as given) is: a file
/// without the MZ signature is a DOS program or none by its name's extension; an MZ file without a
/// new header, or with an LE one or an NE one for OS/2, a DOS program; with a Windows NE header a
/// Windows 3.x program. Any other file no image section is made of (an empty one, a broken PE one)
/// is ERROR_BAD_EXE_FORMAT, and any other status the failure it is.
pub fn of_refusal(status: NtStatus, name: &[u16]) -> Result<u32, Failure> {
    match status {
        STATUS_INVALID_IMAGE_NOT_MZ => by_extension(name).ok_or(BAD),
        STATUS_INVALID_IMAGE_PROTECT
        | STATUS_INVALID_IMAGE_LE_FORMAT
        | STATUS_INVALID_IMAGE_NE_FORMAT => Ok(SCS_DOS_BINARY),
        STATUS_INVALID_IMAGE_WIN_16 => Ok(SCS_WOW_BINARY),
        STATUS_INVALID_IMAGE_FORMAT
        | STATUS_MAPPED_FILE_SIZE_ZERO
        | STATUS_INVALID_FILE_FOR_SECTION => Err(BAD),
        status => Err(Failure::Status(status)),
    }
}

/// GetBinaryTypeW's work over a name: the file opened as CreateProcess opens an image, an image
/// section made of it (the file closed then) and its description asked (the section closed then).
fn type_of(name: &Wide) -> Result<u32, Failure> {
    let path = NtPath::of(name.terminated()).ok_or(Failure::Error(ERROR_PATH_NOT_FOUND))?;
    let file =
        Owned(files::open(&path, OPEN_ACCESS, OPEN_SHARE, OPEN_OPTIONS).map_err(Failure::Status)?);
    let section = ntcall::create_image_section(file.0);
    drop(file);
    let section = match section {
        Ok(section) => Owned(section),
        Err(status) => return of_refusal(status, name.text()),
    };
    let image = ntcall::query_image(section.0);
    drop(section);
    of_image(&image.map_err(Failure::Status)?)
}

/// The export's answer: the type written where asked and TRUE, or the refusal's error set and
/// FALSE.
fn typed(result: Result<u32, Failure>, binary_type: Option<Out<'_, u32>>) -> u32 {
    bool_answer(result.map(|kind| {
        if let Some(mut binary_type) = binary_type {
            binary_type.set(kind);
        }
    }))
}

/// GetBinaryTypeW: the binary type of the file `name` names into `*binary_type`; FALSE with the
/// error when it is not a program or cannot be read.
///
/// # Safety
///
/// `name` is a NUL-terminated string; `binary_type` is null or writable.
#[unsafe(export_name = "f2k_export_GetBinaryTypeW")]
pub unsafe extern "system" fn get_binary_type_w(name: *const u16, binary_type: *mut u32) -> u32 {
    // SAFETY: the caller's string, and its dword when given (the contract).
    let (name, binary_type) = unsafe { (InWStr::new(name), Out::optional(binary_type)) };
    typed(
        files::wide(&name).and_then(|name| type_of(&name)),
        binary_type,
    )
}

/// GetBinaryTypeA: GetBinaryTypeW's work, the name converted through the ANSI code page.
///
/// # Safety
///
/// As GetBinaryTypeW's, the name narrow.
#[unsafe(export_name = "f2k_export_GetBinaryTypeA")]
pub unsafe extern "system" fn get_binary_type_a(name: *const u8, binary_type: *mut u32) -> u32 {
    // SAFETY: the caller's string (null: the empty one), and its dword when given (the contract).
    let (name, binary_type) = unsafe { (InStr::optional(name), Out::optional(binary_type)) };
    typed(
        files::widen(name.as_ref()).and_then(|name| type_of(&name)),
        binary_type,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// A program's description: an i386 executable for the console subsystem.
    fn program() -> SectionImageInformation {
        SectionImageInformation {
            subsystem_type: 3,
            image_characteristics: 0x010F,
            machine: IMAGE_FILE_MACHINE_I386,
            ..SectionImageInformation::default()
        }
    }

    /// An i386 executable is a Windows program, a POSIX one by its subsystem; a DLL, another
    /// machine's image or one not marked executable is none.
    #[test]
    fn the_description_decides_an_image() {
        assert_eq!(of_image(&program()), Ok(SCS_32BIT_BINARY));
        let gui = SectionImageInformation {
            subsystem_type: 2,
            ..program()
        };
        assert_eq!(of_image(&gui), Ok(SCS_32BIT_BINARY));
        let posix = SectionImageInformation {
            subsystem_type: IMAGE_SUBSYSTEM_POSIX_CUI,
            ..program()
        };
        assert_eq!(of_image(&posix), Ok(SCS_POSIX_BINARY));
        let dll = SectionImageInformation {
            image_characteristics: 0x210E,
            ..program()
        };
        assert_eq!(of_image(&dll), Err(BAD));
        let alpha = SectionImageInformation {
            machine: 0x0184,
            ..program()
        };
        assert_eq!(of_image(&alpha), Err(BAD));
        let object = SectionImageInformation {
            image_characteristics: 0x0100,
            ..program()
        };
        assert_eq!(of_image(&object), Err(BAD));
    }

    /// A file without MZ is typed by its name's extension, in any case, after its last separator.
    #[test]
    fn a_file_without_mz_is_typed_by_its_extension() {
        let typed = |file_name: &str| of_refusal(STATUS_INVALID_IMAGE_NOT_MZ, &name(file_name));
        assert_eq!(typed("SCRATCH\\notexe.exe"), Ok(SCS_DOS_BINARY));
        assert_eq!(typed("A.COM"), Ok(SCS_DOS_BINARY));
        assert_eq!(typed("a.Exe"), Ok(SCS_DOS_BINARY));
        assert_eq!(typed("a.pif"), Ok(SCS_PIF_BINARY));
        assert_eq!(typed("SCRATCH\\notexe.txt"), Err(BAD));
        assert_eq!(typed("a.bat"), Err(BAD));
        assert_eq!(typed("a.exe.txt"), Err(BAD));
        assert_eq!(typed("dir.exe\\file"), Err(BAD));
        assert_eq!(typed("dir.exe/file"), Err(BAD));
        assert_eq!(typed("exe"), Err(BAD));
    }

    /// The section's other refusals: a DOS program (no new header, an LE one or an OS/2 NE one),
    /// a Windows 3.x program by its NE header; an empty file, a broken PE one or a file no section
    /// is made of none, whatever its name; any other status its failure.
    #[test]
    fn the_section_refusals_type_the_rest() {
        let exe = name("a.exe");
        assert_eq!(
            of_refusal(STATUS_INVALID_IMAGE_PROTECT, &exe),
            Ok(SCS_DOS_BINARY)
        );
        assert_eq!(
            of_refusal(STATUS_INVALID_IMAGE_LE_FORMAT, &exe),
            Ok(SCS_DOS_BINARY)
        );
        assert_eq!(
            of_refusal(STATUS_INVALID_IMAGE_WIN_16, &exe),
            Ok(SCS_WOW_BINARY)
        );
        assert_eq!(
            of_refusal(STATUS_INVALID_IMAGE_NE_FORMAT, &exe),
            Ok(SCS_DOS_BINARY)
        );
        for status in [
            STATUS_INVALID_IMAGE_FORMAT,
            STATUS_MAPPED_FILE_SIZE_ZERO,
            STATUS_INVALID_FILE_FOR_SECTION,
        ] {
            assert_eq!(of_refusal(status, &exe), Err(BAD), "{status:#x}");
        }
        assert_eq!(
            of_refusal(0xC000_0022, &exe),
            Err(Failure::Status(0xC000_0022))
        );
    }
}
