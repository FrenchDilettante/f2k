//! The process parameters block: RTL_USER_PROCESS_PARAMETERS, the NT structure the PEB's
//! ProcessParameters (PEB+0x10) points at — the standard handles, the image's path, the command
//! line and the environment block, as programs (and the platform's own user-mode code) read them.
//!
//! The block leads the parameters pages ([`crate::user::PARAMS_PAGE`]), normalized (its strings'
//! buffers are absolute addresses), its strings after it on the same pages, UTF-16 as the
//! platform's are. kernel32 makes its narrow command line (GetCommandLineA's) and startup
//! information (GetStartupInfoA's) from the block, in user mode and on the process heap, as Windows
//! 2000's does.
//!
//! The kernel writes a boot's program's block alone: a process another process creates
//! (NtCreateProcess) gets its block, its environment and the PEB's pointer from its creator,
//! kernel32's CreateProcess, as on Windows 2000. The kernel writes only the process's starting
//! values and never reads the block back. The
//! current directory starts as the image's own directory, its DOS path alone: ntdll's process
//! start opens its handle, and it is ntdll's to change from then on (RtlSetCurrentDirectory_U) and
//! to resolve relative paths against (its handle the root of the NT names it makes). The
//! environment block the block's Environment points at is user mode's from the start, as on Windows
//! 2000: the kernel maps it ([`ENVIRONMENT_BLOCK`]) holding the variables every process starts
//! with ([`ENVIRONMENT`]), and ntdll's environment functions edit it and move it to a larger
//! allocation when it outgrows its region.

use rtl::cp1252::MB_TO_WC;
use rtl::nt::UnicodeString;
use rtl::params::{CurrentDirectory, ProcessParameters};

use crate::user::shared::NT_SYSTEM_ROOT;

/// The block's size: RTL_USER_PROCESS_PARAMETERS on NT 5.0, x86, the type ntdll builds a new
/// process's block with (`rtl::params`), its pointers 32-bit.
pub const SIZE: u32 = core::mem::size_of::<ProcessParameters<u32>>() as u32;

/// RTL_USER_PROC_PARAMS_NORMALIZED: the strings' buffers are addresses, not offsets.
pub const NORMALIZED: u32 = rtl::params::NORMALIZED;

/// The room of a path string: MAX_PATH characters.
pub const PATH_ROOM: u32 = 2 * 260;
/// Where the block's strings sit on the pages, from the block: the current directory, the image's
/// path, and (on the second page) the command line.
pub const CURRENT_DIRECTORY_BUFFER: u32 = SIZE;
pub const IMAGE_PATH_BUFFER: u32 = CURRENT_DIRECTORY_BUFFER + PATH_ROOM;
pub const COMMAND_LINE_BUFFER: u32 = 0x1000;
/// The command line's room: twice the narrow command line's.
pub const COMMAND_LINE_ROOM: u32 = 0x800;
/// The pages the block and its strings take.
pub const PAGES: u32 = 2;
/// The environment block's starting region, which the block's Environment points at: the
/// starting variables ([`ENVIRONMENT`]) at its start, user mode's from then on (ntdll's
/// RtlSetEnvironmentVariable edits it in place, and moves it to a larger allocation when it
/// outgrows the region, releasing this one). Windows 2000's address: the lowest a process can
/// allocate, below the parameters pages.
pub const ENVIRONMENT_BLOCK: u32 = 0x0001_0000;
/// The region's size in pages.
pub const ENVIRONMENT_BLOCK_PAGES: u32 = 5;

/// The variables every process starts with, each `NAME=value` as the parts that make it, in the
/// order Windows keeps an environment block (sorted by name, without regard to case) and spelled
/// as Windows 2000 spells them. The system's paths are under the system root, the shared
/// page's NtSystemRoot ([`NT_SYSTEM_ROOT`]).
pub const ENVIRONMENT: [&[&[u8]]; 7] = [
    &[b"COMPUTERNAME=QEMU"],
    &[b"ComSpec=", NT_SYSTEM_ROOT, b"\\system32\\cmd.exe"],
    &[b"PATH=", NT_SYSTEM_ROOT, b"\\system32;", NT_SYSTEM_ROOT],
    &[b"PATHEXT=.COM;.EXE;.BAT;.CMD"],
    &[b"SystemRoot=", NT_SYSTEM_ROOT],
    &[b"USERNAME=jeb"],
    &[b"windir=", NT_SYSTEM_ROOT],
];

/// The starting environment block's room in bytes: the variables, in UTF-16, fit it.
pub const ENVIRONMENT_ROOM: usize = 0x400;

/// The starting environment block ([`ENVIRONMENT`]) in UTF-16 into `out`: each entry
/// NUL-terminated, a final NUL after the last; the bytes written.
pub fn environment(out: &mut [u8; ENVIRONMENT_ROOM]) -> usize {
    let mut at = 0;
    for entry in ENVIRONMENT {
        for part in entry {
            at += widen(part, &mut out[at..]);
        }
        // The entry's terminator.
        out[at..at + 2].fill(0);
        at += 2;
    }
    out[at..at + 2].fill(0);
    at + 2
}

/// The standard handles the block carries, per the real-machine trace
/// (`tests/core/hello/trace.txt`): the GetFileType probes after each GetStdHandle, and the
/// WriteFile that prints, name stdin 3, stdout 7, stderr 0xB — the console server's first three
/// handles (`rtl::console::STANDARD_HANDLES`). All three carry the console tag (the low two bits
/// set).
pub(crate) const STD_INPUT: u32 = 3;
pub(crate) const STD_OUTPUT: u32 = 0x07;
pub(crate) const STD_ERROR: u32 = 0x0B;

/// The ANSI path limit, terminator included.
const MAX_PATH: usize = 260;
/// The module file name's room (the image's path in its Win32 form, "C:\RET0.EXE"), terminator
/// included.
pub const MODULE_ROOM: usize = MAX_PATH;

/// A UNICODE_STRING of `length` bytes in a buffer of `maximum` at `buffer`.
fn unicode_string(length: u32, maximum: u32, buffer: u32) -> UnicodeString<u32> {
    UnicodeString {
        length: length as u16,
        maximum_length: maximum as u16,
        buffer,
    }
}

/// Code page 1252 text into UTF-16 (little-endian) in `out`: the bytes written.
pub fn widen(text: &[u8], out: &mut [u8]) -> usize {
    let mut written = 0;
    for (&byte, unit) in text.iter().zip(out.chunks_exact_mut(2)) {
        unit.copy_from_slice(&MB_TO_WC[byte as usize].to_le_bytes());
        written += 2;
    }
    written
}

/// What the block records, its strings already placed.
pub struct Header {
    /// The block's address (its strings follow it).
    pub base: u32,
    /// The bytes of the command line, the image's path and the current directory, in UTF-16.
    pub command_line: u32,
    pub image_path: u32,
    pub current_directory: u32,
    /// The environment block's address.
    pub environment: u32,
    /// The standard input, output and error handles.
    pub standard: [u32; 3],
}

/// The block: normalized, its strings' buffers on its pages, the standard handles and the
/// environment block's address, and the startup values the capture's STARTUPINFOA shows
/// (GetStartupInfoA copies them out): the window one line down (StartingY 1), 100 by 100, shown
/// normally (SW_SHOWNORMAL), no STARTF_* flags; no title, desktop, shell information or runtime
/// data, and no DLL search path (the loader has none to give). The current directory has no
/// handle: ntdll's process start opens it.
pub fn header(fields: &Header) -> ProcessParameters<u32> {
    let total = COMMAND_LINE_BUFFER + COMMAND_LINE_ROOM;
    ProcessParameters {
        maximum_length: total,
        length: total,
        flags: NORMALIZED,
        standard_input: fields.standard[0],
        standard_output: fields.standard[1],
        standard_error: fields.standard[2],
        current_directory: CurrentDirectory {
            dos_path: unicode_string(
                fields.current_directory,
                PATH_ROOM,
                fields.base + CURRENT_DIRECTORY_BUFFER,
            ),
            handle: 0,
        },
        image_path_name: unicode_string(
            fields.image_path,
            PATH_ROOM,
            fields.base + IMAGE_PATH_BUFFER,
        ),
        command_line: unicode_string(
            fields.command_line,
            COMMAND_LINE_ROOM,
            fields.base + COMMAND_LINE_BUFFER,
        ),
        environment: fields.environment,
        starting_y: 1,
        count_x: 100,
        count_y: 100,
        show_window_flags: 1,
        ..ProcessParameters::default()
    }
}

/// The module file name the image at volume path `module` has (the parameters' ImagePathName,
/// GetModuleFileNameA's answer): its Win32 form, drive and all, upper-cased as the volume's 8.3
/// entries store it ("C:\CORPUS\RUNTIME.EXE"). CreateFileA resolves it back to the image.
pub fn module_file_name(module: &[u8], out: &mut [u8; MODULE_ROOM]) -> usize {
    let path = crate::user::volume_path(module);
    let length = (3 + path.len()).min(MODULE_ROOM - 1);
    out[..3].copy_from_slice(b"C:\\");
    out[3..length].copy_from_slice(&path[..length - 3]);
    out[..length].make_ascii_uppercase();
    length
}

/// The current directory a process starts in: the directory of the image's Win32 path, with its
/// trailing separator (`C:\` for the root, `C:\DIR\` otherwise), into `out`; its length.
pub fn starting_directory(image_path: &[u8], out: &mut [u8; MODULE_ROOM]) -> usize {
    let length = image_path
        .iter()
        .rposition(|&byte| byte == b'\\')
        .map_or(0, |at| at + 1)
        .min(MODULE_ROOM);
    out[..length].copy_from_slice(&image_path[..length]);
    length
}

/// Map the parameters pages at [`crate::user::PARAMS_PAGE`] into `process`'s address space (the
/// current one) and write the block: the command line, the image's Win32 path (from its volume
/// path `module`), the current directory (the image's own), the standard handles and the
/// environment block's address. The environment block's region is mapped too, the starting
/// variables written at its start. The pages are mapped in one hold of the address space, and
/// written once it is released.
#[cfg(target_arch = "x86")]
pub fn map(process: &crate::process::Process, command_line: &[u8], module: &[u8]) {
    use rtl::pod::Pod;

    use crate::mem::{paging::PAGE_SIZE, vm};
    use crate::user::syscall::write_user;
    assert!(
        command_line.len() < COMMAND_LINE_ROOM as usize / 2,
        "command line too long for the parameters"
    );
    let base = crate::user::PARAMS_PAGE;
    process.with_space(|space| {
        for page in 0..PAGES {
            vm::map_zeroed(space, base + page * PAGE_SIZE, vm::PAGE_READWRITE);
        }
        for page in 0..ENVIRONMENT_BLOCK_PAGES {
            vm::map_zeroed(
                space,
                ENVIRONMENT_BLOCK + page * PAGE_SIZE,
                vm::PAGE_READWRITE,
            );
        }
    });
    let mut name = [0u8; MODULE_ROOM];
    let name_length = module_file_name(module, &mut name);
    // The boot's first program names the console every program shares.
    crate::csr::name_console(&name[..name_length]);
    // The pages are fresh, mapped and writable: the writes cannot fail.
    let mut wide = [0u8; COMMAND_LINE_ROOM as usize];
    let command_line_bytes = widen(command_line, &mut wide[..COMMAND_LINE_ROOM as usize - 2]);
    let _ = write_user(base + COMMAND_LINE_BUFFER, &wide[..command_line_bytes]);
    let image_path_bytes = widen(&name[..name_length], &mut wide[..PATH_ROOM as usize - 2]);
    let _ = write_user(base + IMAGE_PATH_BUFFER, &wide[..image_path_bytes]);
    let mut directory = [0u8; MODULE_ROOM];
    let directory_length = starting_directory(&name[..name_length], &mut directory);
    let current_directory_bytes = widen(
        &directory[..directory_length],
        &mut wide[..PATH_ROOM as usize - 2],
    );
    let _ = write_user(
        base + CURRENT_DIRECTORY_BUFFER,
        &wide[..current_directory_bytes],
    );
    let block = header(&Header {
        base,
        command_line: command_line_bytes as u32,
        image_path: image_path_bytes as u32,
        current_directory: current_directory_bytes as u32,
        environment: ENVIRONMENT_BLOCK,
        standard: [STD_INPUT, STD_OUTPUT, STD_ERROR],
    });
    let _ = write_user(base, block.as_bytes());
    let mut environment_block = [0u8; ENVIRONMENT_ROOM];
    let environment_bytes = environment(&mut environment_block);
    let _ = write_user(ENVIRONMENT_BLOCK, &environment_block[..environment_bytes]);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The NT 5.0 layout user code reads.
    #[test]
    fn the_block_is_the_nt_layout() {
        assert_eq!(SIZE, 0x290);
    }

    /// The block: normalized, its strings' buffers at their places after it, their lengths in
    /// bytes, the environment's address and the standard handles, the capture's startup values.
    #[test]
    fn the_block_points_at_its_strings() {
        use rtl::pod::Pod;
        let base = 0x0002_0000;
        let block = header(&Header {
            base,
            command_line: 8,
            image_path: 22,
            current_directory: 6,
            environment: ENVIRONMENT_BLOCK,
            standard: [3, 7, 11],
        });
        assert_eq!(block.flags, NORMALIZED);
        assert_eq!(block.length, block.maximum_length);
        assert_eq!(
            (block.command_line.length, block.command_line.buffer),
            (8, base + COMMAND_LINE_BUFFER)
        );
        assert_eq!(
            (block.image_path_name.length, block.image_path_name.buffer),
            (22, base + IMAGE_PATH_BUFFER)
        );
        let directory = block.current_directory.dos_path;
        assert_eq!(
            (directory.length, directory.maximum_length, directory.buffer),
            (6, PATH_ROOM as u16, base + CURRENT_DIRECTORY_BUFFER)
        );
        assert_eq!(block.environment, ENVIRONMENT_BLOCK);
        assert_eq!(
            (
                block.standard_input,
                block.standard_output,
                block.standard_error
            ),
            (3, 7, 11)
        );
        assert_eq!(block.dll_path, UnicodeString::default(), "no DLL path");
        // The startup values GetStartupInfoA copies out (StartingX to ShowWindowFlags, at
        // 0x4C..0x70): the capture's.
        let startup: Vec<u32> = block.as_bytes()[0x4C..0x70]
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
            .collect();
        assert_eq!(startup, [0, 1, 100, 100, 0, 0, 0, 0, 1]);
        for string in [
            block.window_title,
            block.desktop_info,
            block.shell_info,
            block.runtime_data,
        ] {
            assert_eq!(string, UnicodeString::default(), "none");
        }
        // Nothing else: the remaining words are zero, the drive table included.
        let blank = ProcessParameters {
            maximum_length: block.maximum_length,
            length: block.length,
            flags: block.flags,
            standard_input: block.standard_input,
            standard_output: block.standard_output,
            standard_error: block.standard_error,
            current_directory: block.current_directory,
            image_path_name: block.image_path_name,
            command_line: block.command_line,
            environment: block.environment,
            starting_y: 1,
            count_x: 100,
            count_y: 100,
            show_window_flags: 1,
            ..ProcessParameters::default()
        };
        assert_eq!(block.as_bytes(), blank.as_bytes());
    }

    /// A process starts in its image's directory, its trailing separator kept (a root's too).
    #[test]
    fn the_starting_directory_is_the_images() {
        let mut out = [0u8; MODULE_ROOM];
        let length = starting_directory(b"C:\\CORPUS\\FILES.EXE", &mut out);
        assert_eq!(&out[..length], b"C:\\CORPUS\\");
        let length = starting_directory(b"C:\\RET0.EXE", &mut out);
        assert_eq!(&out[..length], b"C:\\");
    }

    /// The pages' contents do not overlap: the block and its strings, all on the two pages; the
    /// environment block's region lies below them, both at allocation-granularity bases (Windows
    /// 2000's 0x00010000 and 0x00020000).
    #[test]
    fn the_pages_hold_everything_apart() {
        assert!(IMAGE_PATH_BUFFER + PATH_ROOM <= COMMAND_LINE_BUFFER);
        assert!(COMMAND_LINE_BUFFER + COMMAND_LINE_ROOM <= PAGES * 0x1000);
        assert!(ENVIRONMENT_BLOCK + ENVIRONMENT_BLOCK_PAGES * 0x1000 <= crate::user::PARAMS_PAGE);
        assert_eq!(
            ENVIRONMENT_BLOCK % 0x1_0000,
            0,
            "an allocation-granularity base"
        );
    }

    /// The starting environment: its entries in order, under the system root, sorted by their
    /// upper-cased names as ntdll keeps a block, ended by an empty entry.
    #[test]
    fn the_environment_block_holds_the_starting_variables() {
        let mut out = [0xFFu8; ENVIRONMENT_ROOM];
        let length = environment(&mut out);
        let units: Vec<u16> = out[..length]
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .collect();
        assert_eq!(rtl::env::block_length(&units), units.len());
        let text = String::from_utf16(&units).unwrap();
        let entries: Vec<&str> = text.split('\0').collect();
        assert_eq!(
            entries,
            [
                "COMPUTERNAME=QEMU",
                "ComSpec=C:\\WINNT\\system32\\cmd.exe",
                "PATH=C:\\WINNT\\system32;C:\\WINNT",
                "PATHEXT=.COM;.EXE;.BAT;.CMD",
                "SystemRoot=C:\\WINNT",
                "USERNAME=jeb",
                "windir=C:\\WINNT",
                "",
                "",
            ]
        );
        let names: Vec<String> = entries[..ENVIRONMENT.len()]
            .iter()
            .map(|entry| entry.split('=').next().unwrap().to_ascii_uppercase())
            .collect();
        assert!(names.is_sorted(), "{names:?}");
        assert!(length <= (ENVIRONMENT_BLOCK_PAGES * 0x1000) as usize);
    }

    /// Text widens through code page 1252.
    #[test]
    fn text_widens_through_1252() {
        let mut wide = [0u8; 8];
        assert_eq!(widen(b"A\x80", &mut wide), 4);
        assert_eq!(
            wide[..4],
            [0x41, 0, 0xAC, 0x20],
            "0x80 is the euro sign in 1252"
        );
    }

    /// The module file name is the image's Win32 path: drive-qualified, upper-cased like the
    /// volume's short names, and it resolves back to the volume path the image came from.
    #[test]
    fn the_module_file_name_is_absolute() {
        let mut out = [0u8; MODULE_ROOM];
        let length = module_file_name(b"fileio.exe", &mut out);
        assert_eq!(&out[..length], b"C:\\FILEIO.EXE");
        assert!(crate::user::volume_path(&out[..length]).eq_ignore_ascii_case(b"fileio.exe"));
        let length = module_file_name(b"CORPUS\\runtime.exe", &mut out);
        assert_eq!(&out[..length], b"C:\\CORPUS\\RUNTIME.EXE");
    }
}
