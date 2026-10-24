//! GetBinaryTypeA and GetBinaryTypeW: what kind of program a file is, without running it.
//!
//! Windows 2000's kernel32 decides through an image section: NtCreateSection with SEC_IMAGE over
//! the file, then NtQuerySection's SectionImageInformation, the section's refusal statuses saying
//! what a file that is not a Windows image is. F2K has no NtQuerySection yet, so the headers are
//! read here through the file services kernel32 already uses (NtOpenFile, NtReadFile), to the
//! same answers ([`classify`]); the section path is Windows' and can replace this once
//! NtQuerySection exists.
//!
//! As spawn's capture pins it: a Windows program is SCS_32BIT_BINARY; a DLL, a text file named
//! `.txt` and an empty file are ERROR_BAD_EXE_FORMAT; a file that is not an image but is named
//! `.exe` is SCS_DOS_BINARY (the DOS machine would run it); the name is taken as given (no `.exe`
//! added); a directory is ERROR_ACCESS_DENIED, a missing file ERROR_FILE_NOT_FOUND, a missing
//! directory ERROR_PATH_NOT_FOUND. The type is written only on success, and success leaves the
//! last error alone.

use core::mem::size_of;

use rtl::image::{
    ImageDosHeader,
    ImageFileHeader,
    ImageNtHeaders32,
    ImageOptionalHeader32,
    DOS_MAGIC,
    NT_SIGNATURE,
};
use rtl::status::{nt_success, STATUS_END_OF_FILE};

use crate::base::{set_last_error, set_last_nt_error};
use crate::files::{self, NtPath, Wide, ERROR_PATH_NOT_FOUND, SYNCHRONIZE};
use crate::nt::{self, IoStatus};

/// The binary types (winbase.h's SCS_*).
pub const SCS_32BIT_BINARY: u32 = 0;
pub const SCS_DOS_BINARY: u32 = 1;
pub const SCS_WOW_BINARY: u32 = 2;
pub const SCS_PIF_BINARY: u32 = 3;
pub const SCS_POSIX_BINARY: u32 = 4;

pub const ERROR_BAD_EXE_FORMAT: u32 = 193;

/// The access the file is opened with (to read its headers, as an image is opened: for execution),
/// the share modes an image's open allows, and its options: a file, synchronous I/O.
const FILE_READ_DATA: u32 = 0x0001;
const FILE_EXECUTE: u32 = 0x0020;
const SHARE_AS_AN_IMAGE: u32 = files::FILE_SHARE_READ | files::FILE_SHARE_DELETE;
const OPTIONS: u32 = files::FILE_SYNCHRONOUS_IO_NONALERT | files::FILE_NON_DIRECTORY_FILE;

/// The PE headers' facts the answer turns on: the machine (i386), the characteristics (an
/// executable image, a DLL), the optional header's magic (PE32) and the POSIX subsystem.
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_DLL: u16 = 0x2000;
const PE32_MAGIC: u16 = 0x010B;
const IMAGE_SUBSYSTEM_POSIX_CUI: u16 = 7;
/// A Windows 3.x program's new header signature, "NE".
const NE_SIGNATURE: u16 = 0x454E;

/// The image headers' types: integers only, so any bytes of their size make one.
///
/// # Safety
///
/// Every bit pattern of the type's size is a valid value, and the type is at most
/// [`HEADER_ROOM`] bytes.
pub unsafe trait Plain: Copy {}

// SAFETY: integers only (Windows' header layouts), each at most HEADER_ROOM bytes.
unsafe impl Plain for ImageDosHeader {}
// SAFETY: as above.
unsafe impl Plain for ImageNtHeaders32 {}
// SAFETY: as above.
unsafe impl Plain for u32 {}

/// The largest header read: IMAGE_NT_HEADERS32.
const HEADER_ROOM: usize = size_of::<ImageNtHeaders32>();

const _: () = assert!(
    size_of::<ImageNtHeaders32>()
        == 4 + size_of::<ImageFileHeader>() + size_of::<ImageOptionalHeader32>()
);

/// What the headers are read from: `read` fills the start of `buffer` from `offset` on, answering
/// how many bytes it read (zero past the end) or a failed read's status.
pub trait Source {
    fn read(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize, u32>;
}

/// The `T` at `offset`: none when the source ends before its last byte.
fn fetch<T: Plain>(source: &mut impl Source, offset: u64) -> Result<Option<T>, u32> {
    let mut bytes = [0u8; HEADER_ROOM];
    let bytes = &mut bytes[..size_of::<T>()];
    if source.read(offset, bytes)? < bytes.len() {
        return Ok(None);
    }
    // SAFETY: `T` is plain data (any bytes make one) of `bytes`' size; read unaligned.
    Ok(Some(unsafe {
        core::ptr::read_unaligned(bytes.as_ptr().cast::<T>())
    }))
}

/// Why a file has no binary type: a service's status (its error set through ntdll's mapping), or
/// a Win32 error kernel32 sets itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Status(u32),
    Error(u32),
}

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

/// What the file `source` reads is, for GetBinaryType, its name `name` (as given). An empty file is
/// no program; a file without the MZ signature is a DOS program or none by its extension; an MZ
/// file is a Windows program when its new header is a PE one for the i386 (ERROR_BAD_EXE_FORMAT
/// for a DLL, another machine or a header that is not one's), a POSIX one when its subsystem says
/// so, a Windows 3.x one for an NE header, and a DOS program otherwise.
pub fn classify(source: &mut impl Source, name: &[u16]) -> Result<u32, Refusal> {
    const BAD: Refusal = Refusal::Error(ERROR_BAD_EXE_FORMAT);
    let mut first = [0u8; 2];
    let read = source.read(0, &mut first).map_err(Refusal::Status)?;
    if read == 0 {
        return Err(BAD);
    }
    if read < 2 || u16::from_le_bytes(first) != DOS_MAGIC {
        return by_extension(name).ok_or(BAD);
    }
    let Some(dos) = fetch::<ImageDosHeader>(source, 0).map_err(Refusal::Status)? else {
        return Err(BAD);
    };
    let Ok(at) = u64::try_from(dos.e_lfanew) else {
        return Ok(SCS_DOS_BINARY);
    };
    let Some(signature) = fetch::<u32>(source, at).map_err(Refusal::Status)? else {
        return Ok(SCS_DOS_BINARY);
    };
    if signature != NT_SIGNATURE {
        return Ok(if signature as u16 == NE_SIGNATURE {
            SCS_WOW_BINARY
        } else {
            SCS_DOS_BINARY
        });
    }
    let Some(nt) = fetch::<ImageNtHeaders32>(source, at).map_err(Refusal::Status)? else {
        return Err(BAD);
    };
    let file = nt.file_header;
    let optional = nt.optional_header;
    if file.machine != IMAGE_FILE_MACHINE_I386
        || file.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0
        || file.characteristics & IMAGE_FILE_DLL != 0
        || optional.magic != PE32_MAGIC
    {
        return Err(BAD);
    }
    Ok(if optional.subsystem == IMAGE_SUBSYSTEM_POSIX_CUI {
        SCS_POSIX_BINARY
    } else {
        SCS_32BIT_BINARY
    })
}

/// An open file read at explicit offsets (NtReadFile, synchronous).
struct OpenFile(u32);

impl Source for OpenFile {
    fn read(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize, u32> {
        let mut io_status = IoStatus::default();
        // SAFETY: ntdll's export, into the buffer of its length, at the offset above.
        let status = unsafe {
            nt::NtReadFile(
                self.0,
                0,
                0,
                0,
                &mut io_status,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &offset,
                core::ptr::null(),
            )
        };
        match status {
            STATUS_END_OF_FILE => Ok(0),
            status if nt_success(status) => Ok(io_status.information as usize),
            status => Err(status),
        }
    }
}

/// GetBinaryTypeW's work over a name: the file opened as an image is (a directory refused), its
/// headers read, the file closed.
fn type_of(name: &Wide) -> Result<u32, Refusal> {
    let path = NtPath::of(name.terminated()).ok_or(Refusal::Error(ERROR_PATH_NOT_FOUND))?;
    let file = files::open(
        &path,
        FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE,
        SHARE_AS_AN_IMAGE,
        OPTIONS,
    )
    .map_err(Refusal::Status)?;
    let answer = classify(&mut OpenFile(file), name.text());
    files::close(file);
    answer
}

/// The export's answer: the type written and TRUE, or the refusal's error set and FALSE.
fn answer(result: Result<u32, Refusal>, binary_type: Option<&mut u32>) -> u32 {
    match result {
        Ok(kind) => {
            if let Some(binary_type) = binary_type {
                *binary_type = kind;
            }
            1
        }
        Err(Refusal::Status(status)) => {
            set_last_nt_error(status);
            0
        }
        Err(Refusal::Error(error)) => {
            set_last_error(error);
            0
        }
    }
}

/// GetBinaryTypeW: the binary type of the file `name` names into `*binary_type`; FALSE with the
/// error when it is not a program or cannot be read.
///
/// # Safety
///
/// `name` is a NUL-terminated string; `binary_type` is null or writable.
#[unsafe(export_name = "f2k_export_GetBinaryTypeW")]
pub unsafe extern "system" fn get_binary_type_w(name: *const u16, binary_type: *mut u32) -> u32 {
    // SAFETY: the caller's string and slot.
    let (name, binary_type) = unsafe { (files::wide(name), binary_type.as_mut()) };
    match name {
        Some(name) => answer(type_of(&name), binary_type),
        None => 0,
    }
}

/// GetBinaryTypeA: GetBinaryTypeW's work, the name converted through the ANSI code page.
///
/// # Safety
///
/// As GetBinaryTypeW's, the name narrow.
#[unsafe(export_name = "f2k_export_GetBinaryTypeA")]
pub unsafe extern "system" fn get_binary_type_a(name: *const u8, binary_type: *mut u32) -> u32 {
    // SAFETY: the caller's string and slot.
    let (name, binary_type) = unsafe { (files::widen(name), binary_type.as_mut()) };
    match name {
        Some(name) => answer(type_of(&name), binary_type),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file's bytes, read as the file services read them.
    struct Bytes(Vec<u8>);

    impl Source for Bytes {
        fn read(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize, u32> {
            let start = (offset as usize).min(self.0.len());
            let count = buffer.len().min(self.0.len() - start);
            buffer[..count].copy_from_slice(&self.0[start..start + count]);
            Ok(count)
        }
    }

    fn name(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
        bytes[at..at + value.len()].copy_from_slice(value);
    }

    /// An image's first bytes: MZ, the new header at 0x80, a PE32 for the i386 (an executable,
    /// the console subsystem), as MSVC 6 links a program.
    fn program() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        put(&mut bytes, 0, &DOS_MAGIC.to_le_bytes());
        put(&mut bytes, 0x3C, &0x80u32.to_le_bytes());
        put(&mut bytes, 0x80, &NT_SIGNATURE.to_le_bytes());
        put(&mut bytes, 0x84, &IMAGE_FILE_MACHINE_I386.to_le_bytes());
        put(&mut bytes, 0x84 + 18, &0x010Fu16.to_le_bytes());
        put(&mut bytes, 0x98, &PE32_MAGIC.to_le_bytes());
        put(&mut bytes, 0x98 + 0x44, &3u16.to_le_bytes());
        bytes
    }

    fn classified(bytes: Vec<u8>, file_name: &str) -> Result<u32, Refusal> {
        classify(&mut Bytes(bytes), &name(file_name))
    }

    const BAD: Result<u32, Refusal> = Err(Refusal::Error(ERROR_BAD_EXE_FORMAT));

    /// spawn's binarytype block, as the headers decide it: a program; a DLL, a text file named
    /// .txt and an empty file refused; a text file named .exe a DOS program.
    #[test]
    fn the_captured_files_classify_as_captured() {
        assert_eq!(classified(program(), "spawnkid.exe"), Ok(SCS_32BIT_BINARY));
        let mut dll = program();
        put(&mut dll, 0x84 + 18, &0x210Eu16.to_le_bytes());
        assert_eq!(classified(dll, "C:\\WINNT\\system32\\kernel32.dll"), BAD);
        let text = b"not a program\r\n".to_vec();
        assert_eq!(classified(text.clone(), "SCRATCH\\notexe.txt"), BAD);
        assert_eq!(classified(text, "SCRATCH\\notexe.exe"), Ok(SCS_DOS_BINARY));
        assert_eq!(classified(Vec::new(), "SCRATCH\\empty.txt"), BAD);
    }

    /// A name's extension decides a file that is not an image, in any case, after its last
    /// separator.
    #[test]
    fn a_non_image_is_typed_by_its_extension() {
        let text = || b"echo".to_vec();
        assert_eq!(classified(text(), "A.COM"), Ok(SCS_DOS_BINARY));
        assert_eq!(classified(text(), "a.Exe"), Ok(SCS_DOS_BINARY));
        assert_eq!(classified(text(), "a.pif"), Ok(SCS_PIF_BINARY));
        assert_eq!(classified(text(), "a.bat"), BAD);
        assert_eq!(classified(text(), "a.exe.txt"), BAD);
        assert_eq!(classified(text(), "dir.exe\\file"), BAD);
        assert_eq!(classified(text(), "exe"), BAD);
        assert_eq!(classified(vec![b'M'], "one.exe"), Ok(SCS_DOS_BINARY));
    }

    /// MZ files: a DOS program without a PE header, a Windows 3.x one with an NE header, a POSIX
    /// one by its subsystem; another machine, a PE32+ header, an image not marked executable or
    /// headers cut short refused.
    #[test]
    fn mz_files_are_typed_by_their_new_header() {
        let mut dos = program();
        put(&mut dos, 0x80, b"\0\0\0\0");
        assert_eq!(classified(dos.clone(), "a.exe"), Ok(SCS_DOS_BINARY));
        put(&mut dos, 0x3C, &0x1000u32.to_le_bytes());
        assert_eq!(
            classified(dos.clone(), "a.exe"),
            Ok(SCS_DOS_BINARY),
            "past the end"
        );
        put(&mut dos, 0x3C, &(-4i32).to_le_bytes());
        assert_eq!(
            classified(dos, "a.exe"),
            Ok(SCS_DOS_BINARY),
            "a negative offset"
        );
        let mut win16 = program();
        put(&mut win16, 0x80, b"NE\x05\x0A");
        assert_eq!(classified(win16, "a.exe"), Ok(SCS_WOW_BINARY));
        let mut posix = program();
        put(
            &mut posix,
            0x98 + 0x44,
            &IMAGE_SUBSYSTEM_POSIX_CUI.to_le_bytes(),
        );
        assert_eq!(classified(posix, "a.exe"), Ok(SCS_POSIX_BINARY));
        let mut alpha = program();
        put(&mut alpha, 0x84, &0x0184u16.to_le_bytes());
        assert_eq!(classified(alpha, "a.exe"), BAD);
        let mut plus = program();
        put(&mut plus, 0x98, &0x020Bu16.to_le_bytes());
        assert_eq!(classified(plus, "a.exe"), BAD);
        let mut object = program();
        put(&mut object, 0x84 + 18, &0x0100u16.to_le_bytes());
        assert_eq!(classified(object, "a.exe"), BAD);
        let mut short = program();
        short.truncate(0x100);
        assert_eq!(classified(short, "a.exe"), BAD);
        assert_eq!(classified(b"MZ".to_vec(), "a.exe"), BAD);
    }

    /// A failed read is the read's status.
    #[test]
    fn a_failed_read_is_its_status() {
        struct Failing;
        impl Source for Failing {
            fn read(&mut self, _: u64, _: &mut [u8]) -> Result<usize, u32> {
                Err(0xC000_0022)
            }
        }
        assert_eq!(
            classify(&mut Failing, &name("a.exe")),
            Err(Refusal::Status(0xC000_0022))
        );
    }
}
