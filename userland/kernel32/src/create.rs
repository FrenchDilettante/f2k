//! CreateProcessA and CreateProcessW: a new process running a program, made as Windows 2000's
//! kernel32 makes one (Inside Windows 2000's "Flow of CreateProcess"; MSDN's CreateProcess), over
//! ntdll's services through their typed layer ([`crate::ntcall`]). CreateProcessA converts its
//! strings through the ANSI code page and does CreateProcessW's work ([`create_process`]):
//!
//! 1. The flags: a detached process, a new console and a debugged process take the stub path
//!    (logged; ERROR_CALL_NOT_IMPLEMENTED): F2K has one console and no debugger.
//! 2. The current directory asked for, made full: a directory, or ERROR_DIRECTORY.
//! 3. The program ([`find_program`]): the application name as given (no search, no extension
//!    added), the command line then defaulting to the name quoted; or, without one, the command
//!    line's first name searched for as SearchPath's default search looks (the program's directory,
//!    the current directory, the system directories, the Windows directory, PATH), `.exe` added to
//!    a name without an extension. A quoted name is the text between the quotes; an unquoted one is
//!    tried at each space or tab in turn, so `C:\a b\c d.exe` runs `C:\a.exe` if there is one, then
//!    `C:\a b\c.exe`, then the whole — and a name found with spaces in it is quoted in the command
//!    line the new process gets. The searches' misses leave their error even when a later one
//!    succeeds (the spawn capture's "ret=1 err=2").
//! 4. The image: opened for execution (NtOpenFile), an image section made of it (NtCreateSection
//!    with SEC_IMAGE: a file that is no image is ERROR_BAD_EXE_FORMAT — Windows 2000 hands DOS
//!    programs and batch files to NTVDM and cmd.exe, F2K has neither), described (NtQuerySection: a
//!    DLL, an image for another machine or for another subsystem than the Windows GUI and console
//!    ones is ERROR_BAD_EXE_FORMAT), and its Image File Execution Options asked
//!    (LdrQueryImageFileExecutionOptions: Windows 2000 starts the Debugger they name in the
//!    program's place; F2K starts no debugger, so the answer goes unused).
//! 5. The process: NtCreateProcess of the section, the caller its parent, the caller's inheritable
//!    handles copied when bInheritHandles asks; its PEB's address (ProcessBasicInformation); its
//!    priority class (the flags', else the caller's when idle or below normal, else normal) and its
//!    hard-error mode (the caller's, unless CREATE_DEFAULT_ERROR_MODE).
//! 6. Its parameters ([`push_parameters`], BasePushProcessParameters): the environment (the block
//!    given, an ANSI one converted unless CREATE_UNICODE_ENVIRONMENT, or the caller's own) written
//!    into the new process first (at 0x00010000 in a fresh address space); then a parameters block
//!    made in the caller (RtlCreateProcessParameters: the image's path, the DLL search path, the
//!    current directory, the command line, the window title, desktop, shell information and the C
//!    runtime's data), the startup values and the standard handles set (STARTUPINFO's with
//!    STARTF_USESTDHANDLES, else the caller's for a console program, which shares its console),
//!    written into the new process as RtlCreateProcessParameters left it, denormalized (its
//!    strings' buffers offsets from the block, at 0x00020000 in a fresh address space), and the
//!    PEB's ProcessParameters pointed at it: the new process's ntdll normalizes the block during
//!    its initialization (RtlNormalizeProcessParams), as on Windows 2000.
//! 7. Its first thread: the stack the image asks (BaseCreateStack in the new process: its
//!    reservation, its commit — two pages at least, what Windows 2000's child is seen to start its
//!    program with — and a guard page: the stack at 0x00130000 down), the context
//!    (BaseProcessStartThunk with EAX the image's entry point and EBX the PEB), NtCreateThread
//!    suspended, then resumed unless CREATE_SUSPENDED. Windows 2000 announces the new process to
//!    the base server between the two (CsrClientCallServer); F2K has no csrss (a known gap): the
//!    kernel tracks its processes itself.
//!
//! Every failure undoes what was made — the file and section closed, a process made terminated and
//! its handle closed, the parameters block freed — and sets the error Windows 2000 sets; success
//! fills PROCESS_INFORMATION with the process and thread handles and ids. The steps holding paths
//! and structures are not inlined: their buffers stay off each other's frames (kernel32's frames
//! stay within a page, no stack probe).

use core::mem::{offset_of, size_of};
use core::ops::Deref;

use rtl::params::{CountedString, CurrentDirectory, DriveDirectory};
use rtl::peb::Peb;
use rtl::pod::Pod;

use crate::base::{
    self,
    last_error,
    under_peb_lock,
    SecurityAttributes,
    WideUnits,
    CURRENT_PROCESS,
};
use crate::edge::{
    caller_bytes,
    wide_units,
    wide_units_of,
    EnvironmentBlock,
    In,
    InStr,
    InWStr,
    Out,
};
use crate::env;
use crate::error::{bool_answer, Failure};
use crate::files::names::file_attributes;
use crate::files::search::{directory_of, search_default, search_list};
use crate::files::{self, NtPath, Wide, MAX_PATH};
use crate::heap::{HeapArray, Owned};
use crate::nt::ClientId;
use crate::ntcall::{self, NtStatus, ParameterStrings, SectionImageInformation, Source};
use crate::thread;

/// The creation flags CreateProcess reads.
const DEBUG_PROCESS: u32 = 0x0000_0001;
const DEBUG_ONLY_THIS_PROCESS: u32 = 0x0000_0002;
const CREATE_SUSPENDED: u32 = 0x0000_0004;
const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
const CREATE_DEFAULT_ERROR_MODE: u32 = 0x0400_0000;

/// The flags that take the stub path: a detached process, a new console, a debugged process.
const UNSUPPORTED: u32 =
    DETACHED_PROCESS | CREATE_NEW_CONSOLE | DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS;

/// STARTUPINFO's flags that make its standard-handle fields meaningful: STARTF_USESTDHANDLES
/// (STARTF_USEHOTKEY and STARTF_HASSHELLDATA ride in them too).
const STARTF_STANDARD_FIELDS: u32 = 0x0100 | 0x0200 | 0x0400;

/// The Win32 errors CreateProcess sets itself.
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_BAD_EXE_FORMAT: u32 = 193;
const ERROR_DIRECTORY: u32 = 267;

const STATUS_ACCESS_VIOLATION: NtStatus = 0xC000_0005;

/// The section's refusals of a file that is no Windows image: not a PE file at all (no MZ, an NE,
/// LE or Windows 3.x one), an empty file, a file no image section can be made of.
const NOT_AN_IMAGE: [NtStatus; 8] = [
    0xC000_0020, // STATUS_INVALID_FILE_FOR_SECTION
    0xC000_007B, // STATUS_INVALID_IMAGE_FORMAT
    0xC000_011B, // STATUS_INVALID_IMAGE_NE_FORMAT
    0xC000_011E, // STATUS_MAPPED_FILE_SIZE_ZERO
    0xC000_012E, // STATUS_INVALID_IMAGE_LE_FORMAT
    0xC000_012F, // STATUS_INVALID_IMAGE_NOT_MZ
    0xC000_0130, // STATUS_INVALID_IMAGE_PROTECT
    0xC000_0131, // STATUS_INVALID_IMAGE_WIN_16
];

/// What the image's description must say: an executable, not a DLL (IMAGE_FILE_DLL), for the
/// i386, for the Windows GUI or console subsystem.
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const IMAGE_SUBSYSTEM_WINDOWS_GUI: u32 = 2;
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u32 = 3;

/// The image's open: for execution, synchronizable; shared for reading and deleting, as an image
/// is; a file, synchronous I/O.
const FILE_EXECUTE: u32 = 0x0020;
pub(crate) const OPEN_ACCESS: u32 = files::SYNCHRONIZE | FILE_EXECUTE;
pub(crate) const OPEN_SHARE: u32 = files::FILE_SHARE_READ | files::FILE_SHARE_DELETE;
pub(crate) const OPEN_OPTIONS: u32 =
    files::FILE_SYNCHRONOUS_IO_NONALERT | files::FILE_NON_DIRECTORY_FILE;

/// THREAD_ALL_ACCESS: what the first thread's handle grants.
const THREAD_ALL_ACCESS: u32 = 0x001F_03FF;

/// The memory services' type and protection for the environment and the parameters block.
const MEM_COMMIT: u32 = 0x1000;
const PAGE_READWRITE: u32 = 0x04;

/// The page, the allocation granularity and a MiB: the stack's sizes' units.
const PAGE: u32 = 0x1000;
const GRANULARITY: u32 = 0x1_0000;
const MIB: u32 = 0x10_0000;

/// The committed stack a new process's first thread is seen to start with: two pages. Windows
/// 2000's child commits the image's one page, and its start-up (ntdll's process initialization,
/// on that stack) reaches the guard page below and grows the stack by a page before the program's
/// own code runs, so the program finds two pages committed (the spawn fixture's layout block: the
/// child's StackLimit 0x0012E000, while a second thread, which does not grow, shows one page).
/// F2K's start-up uses less than a page, so the first thread is given the two pages outright, as
/// the boot loader gives a boot's program.
const FIRST_THREAD_COMMIT: u32 = 2 * PAGE;

/// PROCESSINFOCLASS: the hard-error mode and the priority class, and the classes' values
/// CreateProcess tells apart (idle, normal, below normal).
const PROCESS_DEFAULT_HARD_ERROR_MODE: u32 = 12;
const PROCESS_PRIORITY_CLASS: u32 = 18;
const CLASS_IDLE: u8 = 1;
const CLASS_NORMAL: u8 = 2;
const CLASS_BELOW_NORMAL: u8 = 5;

/// The PEB's ProcessParameters, in the new process's PEB.
const PEB_PROCESS_PARAMETERS: usize = offset_of!(Peb<u32>, process_parameters);

/// An ASCII text as UTF-16, at compile time.
const fn ascii<const N: usize>(text: &[u8; N]) -> [u16; N] {
    let mut units = [0u16; N];
    let mut at = 0;
    while at < N {
        units[at] = text[at] as u16;
        at += 1;
    }
    units
}

/// The extension the search adds, and the execution option asked.
const EXE: [u16; 4] = ascii(b".exe");
const DEBUGGER: [u16; 9] = ascii(b"Debugger\0");

const QUOTE: u16 = b'"' as u16;
const SPACE: u16 = b' ' as u16;
const TAB: u16 = b'\t' as u16;

/// The environment a creation hands the new process: the caller's own, or a block given (ANSI,
/// or UTF-16 with CREATE_UNICODE_ENVIRONMENT), each through its final empty entry.
#[derive(Clone, Copy)]
pub enum Environment<'a> {
    Inherited,
    Ansi(&'a [u8]),
    Wide(&'a [u16]),
}

/// A STARTUPINFO's fields, its strings in UTF-16: lpReserved (the shell information), the
/// desktop and the title; the window's place and size, the console's character counts and fill
/// (dwX to dwFillAttribute); the STARTF_* flags; wShowWindow; the C runtime's block
/// (cbReserved2, lpReserved2); the standard handles.
#[derive(Clone, Copy, Default)]
pub struct Startup<'a> {
    pub reserved: Option<&'a [u16]>,
    pub desktop: Option<&'a [u16]>,
    pub title: Option<&'a [u16]>,
    pub values: [u32; 7],
    pub flags: u32,
    pub show_window: u16,
    pub runtime_data: Option<&'a [u8]>,
    pub standard_handles: [u32; 3],
}

/// A creation's arguments, as CreateProcessW takes them, read.
#[derive(Clone, Copy)]
pub struct Request<'a> {
    pub application_name: Option<&'a [u16]>,
    pub command_line: Option<&'a [u16]>,
    pub process_attributes: Option<In<'a, SecurityAttributes>>,
    pub thread_attributes: Option<In<'a, SecurityAttributes>>,
    pub inherit_handles: bool,
    pub flags: u32,
    pub environment: Environment<'a>,
    pub current_directory: Option<&'a [u16]>,
    pub startup: Startup<'a>,
}

/// PROCESS_INFORMATION: the new process's and its first thread's handles and ids.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessInformation {
    pub process: u32,
    pub thread: u32,
    pub process_id: u32,
    pub thread_id: u32,
}

/// The command line a new process gets: the caller's, or one made for it.
enum CommandLine<'a> {
    Given(&'a [u16]),
    Made(HeapArray<u16>),
}

impl Deref for CommandLine<'_> {
    type Target = [u16];

    fn deref(&self) -> &[u16] {
        match self {
            CommandLine::Given(units) => units,
            CommandLine::Made(units) => units,
        }
    }
}

/// The program a creation runs: its full DOS path, and the command line the new process gets.
struct Program<'a> {
    path: Wide,
    command_line: CommandLine<'a>,
}

/// A name made full against the current directory (RtlGetFullPathName_U); none past MAX_PATH or
/// for a name ntdll cannot make full.
fn full_path(name: &Wide) -> Option<Wide> {
    let mut full = Wide {
        units: [0; MAX_PATH + 1],
        length: 0,
    };
    full.length = ntcall::full_path_name(name.terminated(), &mut full.units)?;
    Some(full)
}

/// The current directory asked for, made full: it must name a directory (ERROR_DIRECTORY
/// otherwise, a missing one too).
#[inline(never)]
fn directory(name: &[u16]) -> Result<Wide, Failure> {
    const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    let full = Wide::of(name)
        .and_then(|name| full_path(&name))
        .ok_or(Failure::Error(ERROR_DIRECTORY))?;
    // A failed query's error is set, then the call's own over it.
    let attributes = file_attributes(&full).unwrap_or_else(|failure| {
        failure.report();
        INVALID_FILE_ATTRIBUTES
    });
    if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(Failure::Error(ERROR_DIRECTORY));
    }
    Ok(full)
}

/// The program a creation runs (see the module's third step): the application name as given, or
/// the command line's first name searched for. A missing command line with no application name
/// is a fault for the caller (STATUS_ACCESS_VIOLATION), as Windows 2000's reads through it.
#[inline(never)]
fn find_program<'a>(
    application_name: Option<&[u16]>,
    command_line: Option<&'a [u16]>,
) -> Result<Program<'a>, Failure> {
    if let Some(name) = application_name {
        let name = Wide::of(name).ok_or(Failure::Error(ERROR_PATH_NOT_FOUND))?;
        let path = full_path(&name).ok_or(Failure::Error(ERROR_PATH_NOT_FOUND))?;
        let command_line = match command_line {
            Some(line) => CommandLine::Given(line),
            None => CommandLine::Made(HeapArray::joined(&[&[QUOTE], name.text(), &[QUOTE]])?),
        };
        return Ok(Program { path, command_line });
    }
    let Some(line) = command_line else {
        return Err(Failure::Fault(STATUS_ACCESS_VIOLATION));
    };
    let extension = Wide::of(&EXE).expect("a short extension");
    if line.first() == Some(&QUOTE) {
        let quoted = &line[1..];
        let name = &quoted[..quoted
            .iter()
            .position(|&unit| unit == QUOTE)
            .unwrap_or(quoted.len())];
        let name = Wide::of(name)
            .filter(|name| name.length != 0)
            .ok_or(Failure::Error(ERROR_FILE_NOT_FOUND))?;
        let path = search_default(&name, &extension).ok_or_else(|| Failure::Error(last_error()))?;
        return Ok(Program {
            path,
            command_line: CommandLine::Given(line),
        });
    }
    let ends = line
        .iter()
        .enumerate()
        .filter(|&(_, &unit)| unit == SPACE || unit == TAB)
        .map(|(at, _)| at)
        .chain(core::iter::once(line.len()));
    let mut error = ERROR_FILE_NOT_FOUND;
    for end in ends {
        if end == 0 {
            continue;
        }
        let Some(name) = Wide::of(&line[..end]) else {
            break;
        };
        let Some(path) = search_default(&name, &extension) else {
            error = last_error();
            continue;
        };
        let spaced = name.text().iter().any(|&unit| unit == SPACE || unit == TAB);
        let command_line = if spaced {
            CommandLine::Made(HeapArray::joined(&[
                &[QUOTE],
                name.text(),
                &[QUOTE],
                &line[end..],
            ])?)
        } else {
            CommandLine::Given(line)
        };
        return Ok(Program { path, command_line });
    }
    Err(Failure::Error(error))
}

/// The program's image section: the file opened for execution, the section made of it (the file's
/// handle closed either way).
#[inline(never)]
fn open_image(path: &Wide) -> Result<Owned, Failure> {
    let path = NtPath::of(path.terminated()).ok_or(Failure::Error(ERROR_PATH_NOT_FOUND))?;
    let file =
        Owned(files::open(&path, OPEN_ACCESS, OPEN_SHARE, OPEN_OPTIONS).map_err(Failure::Status)?);
    ntcall::create_image_section(file.0)
        .map(Owned)
        .map_err(|status| {
            if NOT_AN_IMAGE.contains(&status) {
                Failure::Error(ERROR_BAD_EXE_FORMAT)
            } else {
                Failure::Status(status)
            }
        })
}

/// Whether the section's image is a program F2K runs: an executable for the i386, for the Windows
/// GUI or console subsystem (ERROR_BAD_EXE_FORMAT otherwise).
fn check_image(image: &SectionImageInformation) -> Result<(), Failure> {
    let runs = image.image_characteristics & IMAGE_FILE_DLL == 0
        && image.machine == IMAGE_FILE_MACHINE_I386
        && matches!(
            image.subsystem_type,
            IMAGE_SUBSYSTEM_WINDOWS_GUI | IMAGE_SUBSYSTEM_WINDOWS_CUI
        );
    if runs {
        Ok(())
    } else {
        Err(Failure::Error(ERROR_BAD_EXE_FORMAT))
    }
}

/// The image's Image File Execution Options, as Windows 2000 asks them before it makes the
/// process: a Debugger there would be started in the program's place. F2K starts no debugger (a
/// known gap), so the answer goes unused.
#[inline(never)]
fn ask_execution_options(path: &Wide) {
    let mut debugger = [0u8; 2 * MAX_PATH];
    let _ = ntcall::image_file_execution_option(path.text(), &DEBUGGER, &mut debugger);
}

/// The OBJECT_ATTRIBUTES a SECURITY_ATTRIBUTES asks for the new process's or thread's handle.
fn attributes(security: In<'_, SecurityAttributes>) -> crate::nt::ObjectAttributes {
    let security = security.read();
    ntcall::unnamed_attributes(security.inherit_handle != 0, security.security_descriptor)
}

/// The new process's priority class (the flags' first class, else the caller's when it is idle or
/// below normal, else normal) and hard-error mode (the caller's, unless CREATE_DEFAULT_ERROR_MODE:
/// the default, 1), as Windows 2000 sets them; a refusal leaves the kernel's defaults.
fn set_scheduling(process: u32, flags: u32) {
    let mut class = [0u8; 2];
    let parent =
        ntcall::query_information_process(CURRENT_PROCESS, PROCESS_PRIORITY_CLASS, &mut class)
            .map_or(CLASS_NORMAL, |()| class[1]);
    let class = crate::process::class_of(flags).unwrap_or(
        if matches!(parent, CLASS_IDLE | CLASS_BELOW_NORMAL) {
            parent
        } else {
            CLASS_NORMAL
        },
    );
    let _ = ntcall::set_information_process(process, PROCESS_PRIORITY_CLASS, &[0, class]);
    let mut mode = 1u32;
    if flags & CREATE_DEFAULT_ERROR_MODE == 0 {
        let mut own = 0u32;
        if ntcall::query_information_process(
            CURRENT_PROCESS,
            PROCESS_DEFAULT_HARD_ERROR_MODE,
            own.as_bytes_mut(),
        )
        .is_ok()
        {
            mode = own;
        }
    }
    let _ =
        ntcall::set_information_process(process, PROCESS_DEFAULT_HARD_ERROR_MODE, mode.as_bytes());
}

/// The caller's own environment block.
fn own_environment<'a>() -> &'a [u16] {
    let block = base::environment_block();
    // SAFETY: the process's environment block, which ntdll keeps terminated; the caller holds the
    // PEB lock, so ntdll neither edits nor moves it meanwhile.
    unsafe { core::slice::from_raw_parts(block, env::block_length(block)) }
}

/// UTF-16 units written into the new process, where the memory services find room for them: their
/// address there.
fn write_units(process: u32, units: &[u16]) -> Result<usize, Failure> {
    let (at, _) =
        ntcall::allocate_virtual_memory(process, 0, 2 * units.len(), MEM_COMMIT, PAGE_READWRITE)
            .map_err(Failure::Status)?;
    ntcall::write_virtual_memory(process, at, Source::of_units(units), None)
        .map_err(Failure::Status)?;
    Ok(at)
}

/// The environment written into the new process (the caller's own under the PEB lock, a UTF-16
/// block as it is, an ANSI one converted through the ANSI code page): its address there.
#[inline(never)]
fn write_environment(process: u32, environment: Environment) -> Result<usize, Failure> {
    match environment {
        Environment::Inherited => under_peb_lock(|| write_units(process, own_environment())),
        Environment::Wide(units) => write_units(process, units),
        Environment::Ansi(bytes) => {
            let mut units = HeapArray::<u16>::new(bytes.len())?;
            let converted = ntcall::multi_byte_to_unicode(&mut units, bytes);
            write_units(process, &units[..converted])
        }
    }
}

/// The size of the parameters block's structure in the caller (its pointers the caller's) and in
/// the new process (its pointers 32-bit): the same on the target.
const HEADER: usize = size_of::<rtl::params::ProcessParameters<usize>>();
const CHILD_HEADER: usize = size_of::<rtl::params::ProcessParameters<u32>>();

/// The parameters block's structure as the new process gets it, `length` bytes long: denormalized,
/// as RtlCreateProcessParameters made it, each string's buffer its offset from the block (the
/// structure's size in the new process standing for the caller's).
fn in_child(
    header: &rtl::params::ProcessParameters<usize>,
    length: u32,
) -> rtl::params::ProcessParameters<u32> {
    let string = |string: &CountedString<usize>| CountedString {
        length: string.length,
        maximum_length: string.maximum_length,
        buffer: if string.buffer == 0 {
            0
        } else {
            (string.buffer - HEADER + CHILD_HEADER) as u32
        },
    };
    rtl::params::ProcessParameters {
        maximum_length: length,
        length,
        flags: header.flags,
        debug_flags: header.debug_flags,
        console_handle: header.console_handle as u32,
        console_flags: header.console_flags,
        standard_input: header.standard_input as u32,
        standard_output: header.standard_output as u32,
        standard_error: header.standard_error as u32,
        current_directory: CurrentDirectory {
            dos_path: string(&header.current_directory.dos_path),
            handle: header.current_directory.handle as u32,
        },
        dll_path: string(&header.dll_path),
        image_path_name: string(&header.image_path_name),
        command_line: string(&header.command_line),
        environment: header.environment as u32,
        starting_x: header.starting_x,
        starting_y: header.starting_y,
        count_x: header.count_x,
        count_y: header.count_y,
        count_chars_x: header.count_chars_x,
        count_chars_y: header.count_chars_y,
        fill_attribute: header.fill_attribute,
        window_flags: header.window_flags,
        show_window_flags: header.show_window_flags,
        window_title: string(&header.window_title),
        desktop_info: string(&header.desktop_info),
        shell_info: string(&header.shell_info),
        runtime_data: string(&header.runtime_data),
        current_directories: header.current_directories.map(|drive| DriveDirectory {
            flags: drive.flags,
            length: drive.length,
            time_stamp: drive.time_stamp,
            dos_path: string(&drive.dos_path),
        }),
    }
}

/// BasePushProcessParameters (see the module's sixth step): the environment and the parameters
/// block written into the new process, its PEB at `peb` pointed at the block.
#[inline(never)]
fn push_parameters(
    process: u32,
    peb: usize,
    request: &Request,
    program: &Program,
    current_directory: Option<&Wide>,
    image: &SectionImageInformation,
) -> Result<(), Failure> {
    let startup = &request.startup;
    let environment = write_environment(process, request.environment)?;
    let dll_path = search_list(directory_of(program.path.text()))?;
    let own = base::parameters();
    let own_desktop = base::desktop_info();
    let console = image.subsystem_type == IMAGE_SUBSYSTEM_WINDOWS_CUI;
    let mut block = ntcall::create_process_parameters(&ParameterStrings {
        image_path_name: program.path.text(),
        dll_path: &dll_path,
        current_directory: current_directory.map(Wide::text),
        command_line: &program.command_line,
        environment,
        window_title: Some(startup.title.unwrap_or(program.path.text())),
        desktop_info: startup
            .desktop
            .or((!own_desktop.is_empty()).then_some(own_desktop)),
        shell_info: startup.reserved,
        runtime_data: startup.runtime_data,
    })
    .map_err(Failure::Status)?;
    let handles = if startup.flags & STARTF_STANDARD_FIELDS != 0 {
        startup.standard_handles
    } else if console {
        [0, 1, 2].map(base::parameters_standard_handle)
    } else {
        [0; 3]
    };
    let header = block.header_mut();
    header.console_handle = if console { own.console_handle } else { 0 };
    // The ignoring of Ctrl+C is inherited (SetConsoleCtrlHandler's documentation); a new process
    // group starts with it set (CreateProcess's documentation: CREATE_NEW_PROCESS_GROUP disables
    // Ctrl+C in the new process).
    header.console_flags = if request.flags & CREATE_NEW_PROCESS_GROUP != 0 {
        1
    } else {
        own.console_flags
    };
    [
        header.standard_input,
        header.standard_output,
        header.standard_error,
    ] = handles.map(|handle| handle as usize);
    [
        header.starting_x,
        header.starting_y,
        header.count_x,
        header.count_y,
        header.count_chars_x,
        header.count_chars_y,
        header.fill_attribute,
    ] = startup.values;
    header.window_flags = startup.flags;
    header.show_window_flags = u32::from(startup.show_window);
    let strings = block.strings();
    let length = CHILD_HEADER + strings.len();
    let (at, _) = ntcall::allocate_virtual_memory(process, 0, length, MEM_COMMIT, PAGE_READWRITE)
        .map_err(Failure::Status)?;
    let child = in_child(block.header(), length as u32);
    ntcall::write_virtual_memory(process, at, Source::of(child.as_bytes()), None)
        .and_then(|()| {
            ntcall::write_virtual_memory(process, at + CHILD_HEADER, Source::of(strings), None)
        })
        .and_then(|()| {
            let pointer = at as u32;
            ntcall::write_virtual_memory(
                process,
                peb + PEB_PROCESS_PARAMETERS,
                Source::of(pointer.as_bytes()),
                None,
            )
        })
        .map_err(Failure::Status)
}

/// The first thread's stack sizes for the image (its SizeOfStackReserve and SizeOfStackCommit, as
/// BaseCreateStack rounds them: the commit to pages, the reservation to the allocation
/// granularity, a commit reaching the reservation taking a reservation of whole MiBs).
fn stack_sizes(image: &SectionImageInformation) -> (u32, u32) {
    let commit = image.committed_stack_size.max(PAGE).next_multiple_of(PAGE);
    let reserve = match image.maximum_stack_size {
        0 => thread::DEFAULT_STACK_RESERVE,
        size => size.next_multiple_of(GRANULARITY),
    };
    if commit >= reserve {
        (commit.next_multiple_of(MIB), commit)
    } else {
        (reserve, commit)
    }
}

/// kernel32's BaseProcessStartThunk (src/start.s), where a new process's first thread starts.
fn process_start_thunk() -> u32 {
    #[cfg(all(target_arch = "x86", not(test)))]
    {
        unsafe extern "C" {
            #[link_name = "f2k_export_BaseProcessStartThunk"]
            static THUNK: u8;
        }
        // The thunk's code, by address only.
        core::ptr::addr_of!(THUNK) as u32
    }
    #[cfg(any(not(target_arch = "x86"), test))]
    {
        PROCESS_START_THUNK
    }
}

/// BaseProcessStartThunk's stand-in address in the host tests.
#[cfg(any(not(target_arch = "x86"), test))]
pub const PROCESS_START_THUNK: u32 = 0x7C4E_1010;

/// The new process's start (see the module's fifth to seventh steps), once NtCreateProcess has
/// made it: its first thread's handle and the client id.
#[inline(never)]
fn start(
    process: u32,
    request: &Request,
    program: &Program,
    current_directory: Option<&Wide>,
    image: &SectionImageInformation,
) -> Result<(Owned, ClientId), Failure> {
    let basic = ntcall::basic_information(process).map_err(Failure::Status)?;
    set_scheduling(process, request.flags);
    push_parameters(
        process,
        basic.peb_base_address as usize,
        request,
        program,
        current_directory,
        image,
    )?;
    let (reserve, commit) = stack_sizes(image);
    let commit = commit.max(FIRST_THREAD_COMMIT);
    let stack = thread::create_stack(process, reserve, commit).map_err(Failure::Status)?;
    let context = thread::thread_context(
        process_start_thunk(),
        image.transfer_address,
        basic.peb_base_address,
        stack.stack_base as u32,
    );
    let thread_attributes = request.thread_attributes.map(attributes);
    let (thread, client_id) = ntcall::create_thread(
        process,
        THREAD_ALL_ACCESS,
        thread_attributes.as_ref(),
        &context,
        &stack,
        true,
    )
    .map_err(Failure::Status)?;
    let thread = Owned(thread);
    // F2K has no csrss (a known gap): Windows 2000 announces the new process and thread to the
    // base server here (CsrClientCallServer, BasepCreateProcess); the kernel tracks them itself.
    if request.flags & CREATE_SUSPENDED == 0 {
        ntcall::resume_thread(thread.0).map_err(Failure::Status)?;
    }
    Ok((thread, client_id))
}

/// CreateProcessW's work (see the module doc): the new process and its first thread.
pub fn create_process(request: &Request) -> Result<ProcessInformation, Failure> {
    let current_directory = request.current_directory.map(directory).transpose()?;
    let program = find_program(request.application_name, request.command_line)?;
    let section = open_image(&program.path)?;
    let image = ntcall::query_image(section.0).map_err(Failure::Status)?;
    check_image(&image)?;
    ask_execution_options(&program.path);
    let process_attributes = request.process_attributes.map(attributes);
    let process = Owned(
        ntcall::create_process(
            process_attributes.as_ref(),
            CURRENT_PROCESS,
            request.inherit_handles,
            section.0,
        )
        .map_err(Failure::Status)?,
    );
    drop(section);
    match start(
        process.0,
        request,
        &program,
        current_directory.as_ref(),
        &image,
    ) {
        Ok((thread, client_id)) => Ok(ProcessInformation {
            process: process.into_raw(),
            thread: thread.into_raw(),
            process_id: client_id.unique_process as u32,
            thread_id: client_id.unique_thread as u32,
        }),
        Err(failure) => {
            let _ = ntcall::terminate_process(process.0, failure.status());
            Err(failure)
        }
    }
}

/// STARTUPINFOA and STARTUPINFOW: `C` the strings' character (`u8` or `u16`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StartupInfo<C> {
    pub cb: u32,
    pub reserved: *const C,
    pub desktop: *const C,
    pub title: *const C,
    /// dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute.
    pub values: [u32; 7],
    pub flags: u32,
    pub show_window: u16,
    pub reserved2_length: u16,
    pub reserved2: *const u8,
    pub standard_input: u32,
    pub standard_output: u32,
    pub standard_error: u32,
}

#[cfg(target_arch = "x86")]
const _: () = assert!(size_of::<StartupInfo<u8>>() == 68);

/// The stub path's arguments, for its log line.
#[allow(clippy::too_many_arguments)]
fn stub_arguments(
    application_name: usize,
    command_line: usize,
    process_attributes: usize,
    thread_attributes: usize,
    inherit_handles: u32,
    flags: u32,
    environment: usize,
    current_directory: usize,
    startup_info: usize,
    process_information: usize,
) -> [u64; 10] {
    [
        application_name as u64,
        command_line as u64,
        process_attributes as u64,
        thread_attributes as u64,
        u64::from(inherit_handles),
        u64::from(flags),
        environment as u64,
        current_directory as u64,
        startup_info as u64,
        process_information as u64,
    ]
}

/// A caller's optional NUL-terminated string, its terminator left out (copied onto the process
/// heap when unaligned: [`crate::edge::wide_units`]); ERROR_NOT_ENOUGH_MEMORY when that copy finds
/// no room.
fn optional_wide<'a>(string: Option<InWStr<'a>>) -> Result<Option<WideUnits<'a>>, Failure> {
    string
        .map(|string| wide_units(&string).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY)))
        .transpose()
}

/// A caller's optional ANSI string converted through the ANSI code page onto the process heap.
fn optional_ansi(string: Option<InStr<'_>>) -> Result<Option<HeapArray<u16>>, Failure> {
    let Some(string) = string else {
        return Ok(None);
    };
    let bytes = string.bytes();
    let mut units = HeapArray::new(bytes.len())?;
    ntcall::multi_byte_to_unicode(&mut units, bytes);
    Ok(Some(units))
}

/// The environment block a caller passes, read where it is: an ANSI block's bytes, a UTF-16 block's
/// units (copied onto the process heap when unaligned, as a caller's string is: [`WideUnits`]).
enum CallerEnvironment<'a> {
    Inherited,
    Ansi(&'a [u8]),
    Wide(WideUnits<'a>),
}

impl CallerEnvironment<'_> {
    /// The environment the creation hands the new process.
    fn environment(&self) -> Environment<'_> {
        match self {
            CallerEnvironment::Inherited => Environment::Inherited,
            CallerEnvironment::Ansi(bytes) => Environment::Ansi(bytes),
            CallerEnvironment::Wide(units) => Environment::Wide(units),
        }
    }
}

/// The environment block a caller passes, as the flags say it is: UTF-16 with
/// CREATE_UNICODE_ENVIRONMENT, ANSI without.
enum CallerBlock<'a> {
    Ansi(EnvironmentBlock<'a, u8>),
    Wide(EnvironmentBlock<'a, u16>),
}

/// The environment block a caller passes, read through its final empty entry: none for none
/// (the caller's own is inherited). ERROR_NOT_ENOUGH_MEMORY when an unaligned UTF-16 block's copy
/// finds no room.
fn environment(block: Option<CallerBlock<'_>>) -> Result<CallerEnvironment<'_>, Failure> {
    match block {
        None => Ok(CallerEnvironment::Inherited),
        Some(CallerBlock::Wide(block)) => wide_units_of(block.units())
            .map(CallerEnvironment::Wide)
            .ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY)),
        Some(CallerBlock::Ansi(block)) => Ok(CallerEnvironment::Ansi(block.units().bytes())),
    }
}

/// A STARTUPINFO's fields, its strings those given.
fn startup<'a, C>(
    info: &StartupInfo<C>,
    reserved: Option<&'a [u16]>,
    desktop: Option<&'a [u16]>,
    title: Option<&'a [u16]>,
    runtime_data: Option<&'a [u8]>,
) -> Startup<'a> {
    Startup {
        reserved,
        desktop,
        title,
        values: info.values,
        flags: info.flags,
        show_window: info.show_window,
        runtime_data,
        standard_handles: [
            info.standard_input,
            info.standard_output,
            info.standard_error,
        ],
    }
}

/// What CreateProcess reads of its caller besides its strings, made at the export: the
/// STARTUPINFO's C runtime block (cbReserved2 bytes at lpReserved2, none without), the attributes
/// and the environment block.
struct Arguments<'a> {
    runtime_data: Option<&'a [u8]>,
    process_attributes: Option<In<'a, SecurityAttributes>>,
    thread_attributes: Option<In<'a, SecurityAttributes>>,
    environment: Option<CallerBlock<'a>>,
}

/// CreateProcessW's and CreateProcessA's work once the strings are read (the application name,
/// the command line, the current directory, then STARTUPINFO's lpReserved, lpDesktop and
/// lpTitle): the environment block read, the request made, the creation, PROCESS_INFORMATION
/// filled.
fn create_with<C>(
    strings: [Option<&[u16]>; 6],
    arguments: Arguments<'_>,
    info: &StartupInfo<C>,
    inherit_handles: u32,
    flags: u32,
    mut information: Out<'_, ProcessInformation>,
) -> Result<(), Failure> {
    let [application_name, command_line, current_directory, reserved, desktop, title] = strings;
    let environment = environment(arguments.environment)?;
    let request = Request {
        application_name,
        command_line,
        process_attributes: arguments.process_attributes,
        thread_attributes: arguments.thread_attributes,
        inherit_handles: inherit_handles != 0,
        flags,
        environment: environment.environment(),
        current_directory,
        startup: startup(info, reserved, desktop, title, arguments.runtime_data),
    };
    information.set(create_process(&request)?);
    Ok(())
}

/// CreateProcessW (see the module doc): TRUE with PROCESS_INFORMATION filled, or FALSE with the
/// error. A missing STARTUPINFO or PROCESS_INFORMATION faults the caller (STATUS_ACCESS_VIOLATION
/// raised before anything is made), as Windows 2000's reads and writes through them.
///
/// # Safety
///
/// The strings are null or NUL-terminated; the attributes are null or SECURITY_ATTRIBUTES; the
/// environment is null or a block of the kind the flags say; `startup_info` is a STARTUPINFOW and
/// `process_information` a writable PROCESS_INFORMATION.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_CreateProcessW")]
pub unsafe extern "system" fn create_process_w(
    application_name: *const u16,
    command_line: *mut u16,
    process_attributes: *const SecurityAttributes,
    thread_attributes: *const SecurityAttributes,
    inherit_handles: u32,
    flags: u32,
    environment_block: *const u8,
    current_directory: *const u16,
    startup_info: *const StartupInfo<u16>,
    process_information: *mut ProcessInformation,
) -> u32 {
    if flags & UNSUPPORTED != 0 {
        let args = stub_arguments(
            application_name as usize,
            command_line as usize,
            process_attributes as usize,
            thread_attributes as usize,
            inherit_handles,
            flags,
            environment_block as usize,
            current_directory as usize,
            startup_info as usize,
            process_information as usize,
        );
        // SAFETY: the caller's arguments, as the export's kinds read them.
        return unsafe {
            crate::stub::stubbed(&crate::spec::CreateProcessW, "not yet implemented", &args)
        };
    }
    // SAFETY: the caller's structures, when given (the contract).
    let (info, information) = unsafe {
        (
            In::optional(startup_info),
            Out::optional(process_information),
        )
    };
    let (Some(info), Some(information)) = (info, information) else {
        ntcall::raise_status(STATUS_ACCESS_VIOLATION);
    };
    let info = info.read();
    // SAFETY: the caller's strings, its STARTUPINFO's and their C runtime block, its attributes
    // and its environment block (of the kind the flags say), each when given, as the contract
    // says.
    let (strings, arguments) = unsafe {
        (
            [
                application_name,
                command_line.cast_const(),
                current_directory,
                info.reserved,
                info.desktop,
                info.title,
            ]
            .map(|string| InWStr::optional(string)),
            Arguments {
                runtime_data: caller_bytes(info.reserved2, usize::from(info.reserved2_length))
                    .filter(|bytes| !bytes.is_empty()),
                process_attributes: In::optional(process_attributes),
                thread_attributes: In::optional(thread_attributes),
                environment: (!environment_block.is_null()).then(|| {
                    if flags & CREATE_UNICODE_ENVIRONMENT != 0 {
                        CallerBlock::Wide(EnvironmentBlock::new(environment_block.cast()))
                    } else {
                        CallerBlock::Ansi(EnvironmentBlock::new(environment_block))
                    }
                }),
            },
        )
    };
    // Every string read (and copied where unaligned), then the first failure answered.
    let read = strings.map(optional_wide);
    let created = (|| {
        let mut strings = [None, None, None, None, None, None];
        for (slot, string) in strings.iter_mut().zip(read) {
            *slot = string?;
        }
        let strings = strings.each_ref().map(|string| string.as_deref());
        create_with(
            strings,
            arguments,
            &info,
            inherit_handles,
            flags,
            information,
        )
    })();
    bool_answer(created)
}

/// CreateProcessA: CreateProcessW's work, its strings (the application name, the command line, the
/// current directory, and STARTUPINFOA's lpReserved, lpDesktop and lpTitle) converted through the
/// ANSI code page first; the environment block is read as the flags say, as CreateProcessW reads
/// it.
///
/// # Safety
///
/// As CreateProcessW's, the strings narrow and `startup_info` a STARTUPINFOA.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_CreateProcessA")]
pub unsafe extern "system" fn create_process_a(
    application_name: *const u8,
    command_line: *mut u8,
    process_attributes: *const SecurityAttributes,
    thread_attributes: *const SecurityAttributes,
    inherit_handles: u32,
    flags: u32,
    environment_block: *const u8,
    current_directory: *const u8,
    startup_info: *const StartupInfo<u8>,
    process_information: *mut ProcessInformation,
) -> u32 {
    if flags & UNSUPPORTED != 0 {
        let args = stub_arguments(
            application_name as usize,
            command_line as usize,
            process_attributes as usize,
            thread_attributes as usize,
            inherit_handles,
            flags,
            environment_block as usize,
            current_directory as usize,
            startup_info as usize,
            process_information as usize,
        );
        // SAFETY: the caller's arguments, as the export's kinds read them.
        return unsafe {
            crate::stub::stubbed(&crate::spec::CreateProcessA, "not yet implemented", &args)
        };
    }
    // SAFETY: the caller's structures, when given (the contract).
    let (info, information) = unsafe {
        (
            In::optional(startup_info),
            Out::optional(process_information),
        )
    };
    let (Some(info), Some(information)) = (info, information) else {
        ntcall::raise_status(STATUS_ACCESS_VIOLATION);
    };
    let info = info.read();
    // SAFETY: as CreateProcessW's, the strings narrow.
    let (strings, arguments) = unsafe {
        (
            [
                application_name,
                command_line.cast_const(),
                current_directory,
                info.reserved,
                info.desktop,
                info.title,
            ]
            .map(|string| InStr::optional(string)),
            Arguments {
                runtime_data: caller_bytes(info.reserved2, usize::from(info.reserved2_length))
                    .filter(|bytes| !bytes.is_empty()),
                process_attributes: In::optional(process_attributes),
                thread_attributes: In::optional(thread_attributes),
                environment: (!environment_block.is_null()).then(|| {
                    if flags & CREATE_UNICODE_ENVIRONMENT != 0 {
                        CallerBlock::Wide(EnvironmentBlock::new(environment_block.cast()))
                    } else {
                        CallerBlock::Ansi(EnvironmentBlock::new(environment_block))
                    }
                }),
            },
        )
    };
    // Every string read and converted, then the first failure answered.
    let read = strings.map(optional_ansi);
    let created = (|| {
        let mut strings = [None, None, None, None, None, None];
        for (slot, string) in strings.iter_mut().zip(read) {
            *slot = string?;
        }
        let strings = strings.each_ref().map(|string| string.as_deref());
        create_with(
            strings,
            arguments,
            &info,
            inherit_handles,
            flags,
            information,
        )
    })();
    bool_answer(created)
}
