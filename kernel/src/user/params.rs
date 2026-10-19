//! The process parameters block: RTL_USER_PROCESS_PARAMETERS, the NT structure the PEB's
//! ProcessParameters (PEB+0x10) points at — the standard handles, the image's path, the command
//! line and the environment block, as programs (and the platform's own user-mode code) read them.
//!
//! The block leads the parameters pages ([`crate::user::PARAMS_PAGE`]), normalized (its strings'
//! buffers are absolute addresses), its strings after it on the same pages, UTF-16 as the
//! platform's are. The service pack's name the PEB's CSDVersion points at shares the pages, past
//! the block's strings. kernel32 makes its narrow command line (GetCommandLineA's) and startup
//! information (GetStartupInfoA's) from the block, in user mode and on the process heap, as Windows
//! 2000's does. The loader's module lists share the first page, past the block's strings
//! (`user::ldr::LOADER_DATA`).
//!
//! The kernel writes only the process's starting values and never reads the block back. The
//! current directory starts as the image's own directory, its DOS path alone: ntdll's process
//! start opens its handle, and it is ntdll's to change from then on (RtlSetCurrentDirectory_U) and
//! to resolve relative paths against (its handle the root of the NT names it makes). The environment
//! block the block's Environment points at is user mode's from the start, as on Windows 2000: the
//! kernel maps it empty ([`ENVIRONMENT_BLOCK`]), and ntdll's environment functions edit it and move
//! it to a larger allocation when it outgrows its region.

// The layouts' fields user code reads, whether the kernel writes them or not (kernel32 and ntdll
// read them by these offsets).
#![allow(dead_code)]

use rtl::cp1252::MB_TO_WC;

/// The block's size: RTL_USER_PROCESS_PARAMETERS on NT 5.0, x86.
pub const SIZE: u32 = 0x290;

/// The block's field offsets.
pub mod offset {
    pub const MAXIMUM_LENGTH: u32 = 0x00;
    pub const LENGTH: u32 = 0x04;
    pub const FLAGS: u32 = 0x08;
    pub const STANDARD_INPUT: u32 = 0x18;
    pub const STANDARD_OUTPUT: u32 = 0x1C;
    pub const STANDARD_ERROR: u32 = 0x20;
    /// CurrentDirectory: a CURDIR, its DosPath (a UNICODE_STRING) then its Handle.
    pub const CURRENT_DIRECTORY: u32 = 0x24;
    pub const DLL_PATH: u32 = 0x30;
    pub const IMAGE_PATH_NAME: u32 = 0x38;
    pub const COMMAND_LINE: u32 = 0x40;
    pub const ENVIRONMENT: u32 = 0x48;
    /// The window's starting place and size, the console's character counts and fill, and the
    /// STARTF_* flags and SW_* value: what kernel32's GetStartupInfoA reports.
    pub const STARTING_X: u32 = 0x4C;
    pub const STARTING_Y: u32 = 0x50;
    pub const COUNT_X: u32 = 0x54;
    pub const COUNT_Y: u32 = 0x58;
    pub const COUNT_CHARS_X: u32 = 0x5C;
    pub const COUNT_CHARS_Y: u32 = 0x60;
    pub const FILL_ATTRIBUTE: u32 = 0x64;
    pub const WINDOW_FLAGS: u32 = 0x68;
    pub const SHOW_WINDOW_FLAGS: u32 = 0x6C;
    /// WindowTitle, DesktopInfo, ShellInfo and RuntimeData: UNICODE_STRINGs (RuntimeData the C
    /// runtime's inherited-handle block, cbReserved2/lpReserved2).
    pub const WINDOW_TITLE: u32 = 0x70;
    pub const DESKTOP_INFO: u32 = 0x78;
    pub const SHELL_INFO: u32 = 0x80;
    pub const RUNTIME_DATA: u32 = 0x88;
}

/// The startup values the block carries (the capture's STARTUPINFOA, as GetStartupInfoA copies it
/// out): the window one line down (StartingY 1), 100 by 100, shown normally (SW_SHOWNORMAL), no
/// STARTF_* flags; no title, desktop, shell information or runtime data.
pub const STARTUP: [(u32, u32); 4] = [
    (offset::STARTING_Y, 1),
    (offset::COUNT_X, 100),
    (offset::COUNT_Y, 100),
    (offset::SHOW_WINDOW_FLAGS, 1),
];

/// RTL_USER_PROC_PARAMS_NORMALIZED: the strings' buffers are addresses, not offsets.
pub const NORMALIZED: u32 = 1;

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
/// The service pack's name the PEB's CSDVersion points at (GetVersionExA's szCSDVersion), past the
/// block's strings on the second page.
pub const CSD_VERSION_BUFFER: u32 = COMMAND_LINE_BUFFER + COMMAND_LINE_ROOM;
pub const CSD_VERSION_TEXT: &[u8] = b"Service Pack 4";
/// The environment block's starting region, which the block's Environment points at: an empty
/// block (two NULs, the region's zeroed pages), user mode's from then on (ntdll's
/// RtlSetEnvironmentVariable edits it in place, and moves it to a larger allocation when it
/// outgrows the region, releasing this one).
pub const ENVIRONMENT_BLOCK: u32 = 0x0035_0000;
/// The region's size in pages.
pub const ENVIRONMENT_BLOCK_PAGES: u32 = 5;

/// The standard handles the block carries, per the real-machine trace (`tests/hello/trace.txt`):
/// the GetFileType probes after each GetStdHandle, and the WriteFile that prints, name stdin 3,
/// stdout 7, stderr 0xB — the console server's first three handles
/// (`rtl::console::STANDARD_HANDLES`). All three carry the console tag (the low two bits set).
pub(crate) const STD_INPUT: u32 = 3;
pub(crate) const STD_OUTPUT: u32 = 0x07;
pub(crate) const STD_ERROR: u32 = 0x0B;

/// The ANSI path limit, terminator included.
const MAX_PATH: usize = 260;
/// The module file name's room (the image's path in its Win32 form, "C:\RET0.EXE"), terminator
/// included.
pub const MODULE_ROOM: usize = MAX_PATH;

/// A UNICODE_STRING: its length and room in bytes, and its buffer.
pub fn unicode_string(length: u32, maximum: u32, buffer: u32) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[0..2].copy_from_slice(&(length as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&(maximum as u16).to_le_bytes());
    bytes[4..8].copy_from_slice(&buffer.to_le_bytes());
    bytes
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

/// The block's bytes.
pub fn header(fields: &Header) -> [u8; SIZE as usize] {
    let mut block = [0u8; SIZE as usize];
    let mut put = |at: u32, bytes: &[u8]| {
        block[at as usize..at as usize + bytes.len()].copy_from_slice(bytes)
    };
    let total = COMMAND_LINE_BUFFER + COMMAND_LINE_ROOM;
    put(offset::MAXIMUM_LENGTH, &total.to_le_bytes());
    put(offset::LENGTH, &total.to_le_bytes());
    put(offset::FLAGS, &NORMALIZED.to_le_bytes());
    put(offset::STANDARD_INPUT, &fields.standard[0].to_le_bytes());
    put(offset::STANDARD_OUTPUT, &fields.standard[1].to_le_bytes());
    put(offset::STANDARD_ERROR, &fields.standard[2].to_le_bytes());
    // The current directory's DOS path (no handle: ntdll's process start opens it).
    put(
        offset::CURRENT_DIRECTORY,
        &unicode_string(
            fields.current_directory,
            PATH_ROOM,
            fields.base + CURRENT_DIRECTORY_BUFFER,
        ),
    );
    put(
        offset::IMAGE_PATH_NAME,
        &unicode_string(
            fields.image_path,
            PATH_ROOM,
            fields.base + IMAGE_PATH_BUFFER,
        ),
    );
    put(
        offset::COMMAND_LINE,
        &unicode_string(
            fields.command_line,
            COMMAND_LINE_ROOM,
            fields.base + COMMAND_LINE_BUFFER,
        ),
    );
    put(offset::ENVIRONMENT, &fields.environment.to_le_bytes());
    for (at, value) in STARTUP {
        put(at, &value.to_le_bytes());
    }
    // No DLL search path: the loader has none to give.
    put(offset::DLL_PATH, &unicode_string(0, 0, 0));
    block
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

/// Map the parameters pages at [`crate::user::PARAMS_PAGE`] into `space` (the current address
/// space) and write the block: the command line, the image's Win32 path (from its volume path
/// `module`), the current directory (the image's own), the standard handles and the environment
/// block's address; the service pack's name; and the loader's module lists (`image`, then the system
/// DLLs: see `user::ldr`), the image's entry over the block's ImagePathName. The environment
/// block's region is mapped too, its zeroed pages an empty block.
#[cfg(target_arch = "x86")]
pub fn map(
    space: &mut crate::mem::vm::AddressSpace,
    command_line: &[u8],
    module: &[u8],
    image: crate::user::ldr::Module,
) {
    use crate::mem::{paging::PAGE_SIZE, vm};
    use crate::user::syscall::write_user;
    assert!(
        command_line.len() < COMMAND_LINE_ROOM as usize / 2,
        "command line too long for the parameters"
    );
    let base = crate::user::PARAMS_PAGE;
    for page in 0..PAGES {
        vm::map_zeroed(space, base + page * PAGE_SIZE, vm::PAGE_READWRITE);
    }
    let mut name = [0u8; MODULE_ROOM];
    let name_length = module_file_name(module, &mut name);
    // The pages are fresh, mapped and writable: the writes cannot fail.
    let mut wide = [0u8; COMMAND_LINE_ROOM as usize];
    let command_line_bytes = widen(command_line, &mut wide[..COMMAND_LINE_ROOM as usize - 2]);
    let _ = write_user(base + COMMAND_LINE_BUFFER, &wide[..command_line_bytes]);
    let image_path_bytes = widen(&name[..name_length], &mut wide[..PATH_ROOM as usize - 2]);
    let _ = write_user(base + IMAGE_PATH_BUFFER, &wide[..image_path_bytes]);
    let mut directory = [0u8; MODULE_ROOM];
    let directory_length = starting_directory(&name[..name_length], &mut directory);
    let current_directory_bytes =
        widen(&directory[..directory_length], &mut wide[..PATH_ROOM as usize - 2]);
    let _ = write_user(
        base + CURRENT_DIRECTORY_BUFFER,
        &wide[..current_directory_bytes],
    );
    let csd_version_bytes = widen(CSD_VERSION_TEXT, &mut wide);
    let _ = write_user(base + CSD_VERSION_BUFFER, &wide[..csd_version_bytes]);
    let block = header(&Header {
        base,
        command_line: command_line_bytes as u32,
        image_path: image_path_bytes as u32,
        current_directory: current_directory_bytes as u32,
        environment: ENVIRONMENT_BLOCK,
        standard: [STD_INPUT, STD_OUTPUT, STD_ERROR],
    });
    let _ = write_user(base, &block);
    crate::user::ldr::map(image, &name[..name_length]);
    for page in 0..ENVIRONMENT_BLOCK_PAGES {
        vm::map_zeroed(space, ENVIRONMENT_BLOCK + page * PAGE_SIZE, vm::PAGE_READWRITE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The NT 5.0 layout user code reads.
    #[test]
    fn offsets_are_the_nt_layout() {
        assert_eq!(SIZE, 0x290);
        assert_eq!(offset::STANDARD_INPUT, 0x18);
        assert_eq!(offset::CURRENT_DIRECTORY, 0x24);
        assert_eq!(offset::DLL_PATH, 0x30);
        assert_eq!(offset::IMAGE_PATH_NAME, 0x38);
        assert_eq!(offset::COMMAND_LINE, 0x40);
        assert_eq!(offset::ENVIRONMENT, 0x48);
        assert_eq!(offset::SHOW_WINDOW_FLAGS, 0x6C);
        assert_eq!(offset::RUNTIME_DATA, 0x88);
    }

    /// The block: normalized, its strings' buffers at their places after it, their lengths in
    /// bytes, the environment's address and the standard handles, the capture's startup values.
    #[test]
    fn the_block_points_at_its_strings() {
        let base = 0x0032_0000;
        let block = header(&Header {
            base,
            command_line: 8,
            image_path: 22,
            current_directory: 6,
            environment: ENVIRONMENT_BLOCK,
            standard: [3, 7, 11],
        });
        let word =
            |at: u32| u32::from_le_bytes(block[at as usize..at as usize + 4].try_into().unwrap());
        let half =
            |at: u32| u16::from_le_bytes(block[at as usize..at as usize + 2].try_into().unwrap());
        assert_eq!(word(offset::FLAGS), NORMALIZED);
        assert_eq!(word(offset::LENGTH), word(offset::MAXIMUM_LENGTH));
        assert_eq!(
            (half(offset::COMMAND_LINE), word(offset::COMMAND_LINE + 4)),
            (8, base + COMMAND_LINE_BUFFER)
        );
        assert_eq!(
            (
                half(offset::IMAGE_PATH_NAME),
                word(offset::IMAGE_PATH_NAME + 4)
            ),
            (22, base + IMAGE_PATH_BUFFER)
        );
        assert_eq!(
            (
                half(offset::CURRENT_DIRECTORY),
                half(offset::CURRENT_DIRECTORY + 2),
                word(offset::CURRENT_DIRECTORY + 4)
            ),
            (6, PATH_ROOM as u16, base + CURRENT_DIRECTORY_BUFFER)
        );
        assert_eq!(word(offset::ENVIRONMENT), ENVIRONMENT_BLOCK);
        assert_eq!(
            (
                word(offset::STANDARD_INPUT),
                word(offset::STANDARD_OUTPUT),
                word(offset::STANDARD_ERROR)
            ),
            (3, 7, 11)
        );
        assert_eq!(half(offset::DLL_PATH), 0, "no DLL path");
        // The startup values GetStartupInfoA copies out: the capture's.
        let startup: Vec<u32> = (offset::STARTING_X..=offset::SHOW_WINDOW_FLAGS)
            .step_by(4)
            .map(word)
            .collect();
        assert_eq!(startup, [0, 1, 100, 100, 0, 0, 0, 0, 1]);
        for string in [
            offset::WINDOW_TITLE,
            offset::DESKTOP_INFO,
            offset::SHELL_INFO,
            offset::RUNTIME_DATA,
        ] {
            assert_eq!(
                (word(string), word(string + 4)),
                (0, 0),
                "{string:#x}: none"
            );
        }
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

    /// The pages' contents do not overlap: the block and its strings and the service pack's name,
    /// all on the two pages; the environment block's region lies past them.
    #[test]
    fn the_pages_hold_everything_apart() {
        assert!(IMAGE_PATH_BUFFER + PATH_ROOM <= COMMAND_LINE_BUFFER);
        assert!(COMMAND_LINE_BUFFER + COMMAND_LINE_ROOM <= CSD_VERSION_BUFFER);
        assert!(CSD_VERSION_BUFFER + 2 * CSD_VERSION_TEXT.len() as u32 + 2 <= PAGES * 0x1000);
        assert!(crate::user::PARAMS_PAGE + PAGES * 0x1000 <= ENVIRONMENT_BLOCK);
        assert_eq!(ENVIRONMENT_BLOCK % 0x1_0000, 0, "an allocation-granularity base");
        // The longest boot command line fits the block's, terminated.
        assert!(crate::boot::cmdline::MAX_LEN < COMMAND_LINE_ROOM as usize / 2);
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
