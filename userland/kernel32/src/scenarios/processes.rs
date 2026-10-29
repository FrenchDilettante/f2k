//! The processes group: CreateProcessA and CreateProcessW over the stand-in child
//! ([`crate::nt::children`]: the process NtCreateProcess makes, its address space as a new
//! process's is laid out), OpenProcess, GetExitCodeProcess, TerminateProcess on a child,
//! ReadProcessMemory and WriteProcessMemory. The spawn fixture is the contract on the machine;
//! these pin what kernel32 itself decides — the name searched for and the command line the child
//! gets, the services asked and in what order, where the environment, the parameters block and
//! the stack land in the child and what they hold, the first thread's context, the errors kernel32
//! sets, and what every failure undoes.

use super::last_error;
use crate::create::{
    create_process_a,
    create_process_w,
    ProcessInformation,
    StartupInfo,
    PROCESS_START_THUNK,
};
use crate::nt::children::{
    self,
    child_bytes,
    child_dword,
    child_vm,
    fail,
    with_child,
    CHILD,
    CHILD_ENTRY,
    CHILD_ID,
    CHILD_IMAGE_BASE,
    CHILD_IMAGE_SIZE,
    CHILD_PEB,
    CHILD_PROCESS,
    OPENED,
    OPENED_PROCESS,
    OPTIONS_ASKED,
    PARAMETERS_DESTROYED,
    PARAMETERS_MADE,
    SECTION_IMAGE,
};
use crate::nt::files::{calls, Call, CURRENT_DIRECTORY, EXISTENCE_ASKED, EXISTING_PATHS, FILE};
use crate::nt::host::{CLOSED, DEBUG_PRINTS, ENVIRONMENT, FAIL_NEXT, HANDLE, LAST_SECTION};
use crate::nt::threads::{
    CREATED,
    CREATED_ID,
    CREATED_THREAD,
    CREATE_FAILS,
    CURRENT_PROCESS,
    HARD_ERROR_MODE,
    TERMINATED,
    THREADS,
};
use crate::process::{
    get_exit_code_process,
    open_process,
    read_process_memory,
    terminate_process,
    write_process_memory,
};
use crate::thread::context;

/// The last error a call leaves alone, armed before it.
const UNTOUCHED: u32 = 0x0F2F_2F2F;

/// The stand-in process's environment: PATH, and one more variable.
const OWN_ENVIRONMENT: &str = "PATH=C:\\TOOLS\0X=1\0\0";

/// The default search's directories, as the stand-in process has them: the program's, the current
/// one, the system directories, the Windows directory, PATH's.
const SEARCH: &str = "C:\\CORPUS;.;C:\\WINNT\\system32;C:\\WINNT\\system;C:\\WINNT;C:\\TOOLS";

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// A fresh scene: no child, nothing recorded, the stand-in process in `C:\CORPUS\` with
/// [`OWN_ENVIRONMENT`] under the system root `C:\WINNT`, no file existing, the last error armed.
fn setup() {
    children::reset();
    let root = b"C:\\WINNT\0\0";
    for (at, pair) in root.chunks(2).enumerate() {
        crate::shared::host::set(
            crate::shared::NT_SYSTEM_ROOT + 4 * at,
            u32::from(pair[0]) | u32::from(pair[1]) << 16,
        );
    }
    CURRENT_DIRECTORY
        .with(|current| *current.borrow_mut() = "C:\\CORPUS\\".encode_utf16().collect());
    EXISTING_PATHS.with(|existing| existing.borrow_mut().clear());
    EXISTENCE_ASKED.with(|asked| asked.borrow_mut().clear());
    FILE.with(|file| file.borrow_mut().attributes = 0x20);
    ENVIRONMENT.with(|block| {
        let mut block = block.borrow_mut();
        block.fill(0);
        for (at, unit) in OWN_ENVIRONMENT.encode_utf16().enumerate() {
            block[at] = unit;
        }
    });
    HARD_ERROR_MODE.with(|mode| mode.set(1));
    calls();
    CLOSED.with(|closed| closed.borrow_mut().clear());
    CREATED.with(|created| created.borrow_mut().clear());
    TERMINATED.with(|terminated| terminated.borrow_mut().clear());
    DEBUG_PRINTS.with(|prints| prints.borrow_mut().clear());
    crate::base::set_last_error(UNTOUCHED);
}

/// Files that exist, by their full paths.
fn existing(paths: &[&str]) {
    EXISTING_PATHS.with(|existing| {
        *existing.borrow_mut() = paths.iter().map(|path| path.to_string()).collect()
    });
}

fn startup<C>() -> StartupInfo<C> {
    StartupInfo {
        cb: 68,
        reserved: core::ptr::null(),
        desktop: core::ptr::null(),
        title: core::ptr::null(),
        values: [0; 7],
        flags: 0,
        show_window: 0,
        reserved2_length: 0,
        reserved2: core::ptr::null(),
        standard_input: 0,
        standard_output: 0,
        standard_error: 0,
    }
}

/// CreateProcessW of the names, inheriting handles, no attributes: its answer, the last error
/// and PROCESS_INFORMATION.
fn create(
    application_name: Option<&str>,
    command_line: Option<&str>,
    flags: u32,
    environment: *const u8,
    current_directory: Option<&str>,
    info: &StartupInfo<u16>,
) -> (u32, u32, ProcessInformation) {
    let application_name = application_name.map(wide);
    let mut command_line = command_line.map(wide);
    let current_directory = current_directory.map(wide);
    let mut information = ProcessInformation::default();
    let created = unsafe {
        create_process_w(
            application_name
                .as_ref()
                .map_or(core::ptr::null(), |name| name.as_ptr()),
            command_line
                .as_mut()
                .map_or(core::ptr::null_mut(), |line| line.as_mut_ptr()),
            core::ptr::null(),
            core::ptr::null(),
            1,
            flags,
            environment,
            current_directory
                .as_ref()
                .map_or(core::ptr::null(), |directory| directory.as_ptr()),
            info,
            &mut information,
        )
    };
    (created, last_error(), information)
}

/// CreateProcessW of a command line alone.
fn run(command_line: &str) -> (u32, u32, ProcessInformation) {
    create(
        None,
        Some(command_line),
        0,
        core::ptr::null(),
        None,
        &startup(),
    )
}

/// The UNICODE_STRING at `field` in the child's parameters block (denormalized: its buffer an
/// offset from the block), as text.
fn child_string(field: usize) -> String {
    let length = child_dword(PARAMETERS + field) & 0xFFFF;
    let buffer = PARAMETERS + child_dword(PARAMETERS + field + 4) as usize;
    let bytes = child_bytes(buffer, length as usize);
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units).unwrap()
}

/// The child's UTF-16 bytes at `at`, `units` of them, as text (NULs kept).
fn child_text(at: usize, units: usize) -> String {
    let bytes = child_bytes(at, 2 * units);
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units).unwrap()
}

/// The image's open: its access, share and options, and the name opened.
fn image_open() -> (u32, u32, u32, String) {
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

fn closed() -> Vec<u32> {
    CLOSED.with(|closed| std::mem::take(&mut *closed.borrow_mut()))
}

fn made() -> Vec<children::MadeParameters> {
    PARAMETERS_MADE.with(|made| made.borrow().clone())
}

const PARAMETERS: usize = 0x0002_0000;
const ENVIRONMENT_AT: usize = 0x0001_0000;

/// A program run by its full name with a command line: the image opened for execution (shared
/// for reading and deleting, synchronous, no directory), an image section made of it and its
/// Debugger option asked; the process made of the section, the caller its parent, inheriting;
/// its environment written at 0x00010000, its parameters block at 0x00020000 (denormalized, its
/// strings' buffers offsets from the block: the image's path, the command line as given, the
/// caller's current directory, the default search as the DLL path, the image's path as the title;
/// the console program's standard handles the caller's) and the PEB pointed at it; the stack
/// reserved below 0x00130000 with its commit and guard page; the first thread at
/// BaseProcessStartThunk (EAX the entry, EBX the PEB), made suspended and resumed; the file and
/// section closed, the block freed, the handles and ids handed out, the last error untouched.
///
/// Pins: kernel32.CreateProcessW
#[test]
fn create_process_runs_a_program_in_a_new_process() {
    setup();
    let (created, error, information) = create(
        Some("C:\\CORPUS\\SPAWNKID.EXE"),
        Some("spawnkid args one \"two words\""),
        0,
        core::ptr::null(),
        None,
        &startup(),
    );
    assert_eq!((created, error), (1, UNTOUCHED));
    assert_eq!(
        information,
        ProcessInformation {
            process: CHILD_PROCESS,
            thread: CREATED_THREAD,
            process_id: CHILD_ID as u32,
            thread_id: CREATED_ID as u32,
        }
    );
    let (access, share, options, name) = image_open();
    assert_eq!((access, share, options), (0x0010_0020, 0x5, 0x60));
    assert!(name.ends_with("C:\\CORPUS\\SPAWNKID.EXE"), "{name}");
    LAST_SECTION.with(|section| {
        assert_eq!(
            section.get(),
            Some((0x000F_001F, 0x10, 0x0100_0000, HANDLE, None))
        )
    });
    OPTIONS_ASKED.with(|asked| {
        assert_eq!(
            *asked.borrow(),
            [(
                "C:\\CORPUS\\SPAWNKID.EXE".to_string(),
                "Debugger".to_string()
            )]
        )
    });
    with_child(|child| {
        assert_eq!(
            (
                child.access,
                child.parent,
                child.inherit_handles,
                child.inheritable,
                child.section
            ),
            (0x001F_0FFF, CURRENT_PROCESS, true, false, HANDLE)
        );
        assert_eq!(
            child.information,
            [(18, vec![0, 2]), (12, vec![1, 0, 0, 0])],
            "a normal class, the caller's hard-error mode"
        );
    });
    assert_eq!(
        child_vm(),
        [
            ("allocate", ENVIRONMENT_AT, 0x1000, 0x1000),
            ("allocate", PARAMETERS, 0x1000, 0x1000),
            ("allocate", 0x0003_0000, 0x10_0000, 0x2000),
            ("allocate", 0x0012_D000, 0x3000, 0x1000),
            ("protect", 0x0012_D000, 0x1000, 0x104),
        ],
        "the environment, the parameters, the stack: its reservation, two pages committed and a guard page"
    );
    assert_eq!(child_dword(CHILD_PEB + 0x10), PARAMETERS as u32);
    assert_eq!(
        child_dword(PARAMETERS + 0x08) & 1,
        0,
        "denormalized: the child's ntdll normalizes it"
    );
    assert_eq!(
        child_dword(PARAMETERS + 0x3C),
        (0x290 + 520 + (2 * SEARCH.encode_utf16().count() + 2).next_multiple_of(4)) as u32,
        "the image's path an offset from the block"
    );
    assert_eq!(child_dword(PARAMETERS + 0x48), ENVIRONMENT_AT as u32);
    assert_eq!(
        child_dword(PARAMETERS) as usize,
        0x290 + made_room(),
        "the block's length"
    );
    assert_eq!(
        child_text(ENVIRONMENT_AT, OWN_ENVIRONMENT.len()),
        OWN_ENVIRONMENT
    );
    assert_eq!(child_string(0x38), "C:\\CORPUS\\SPAWNKID.EXE");
    assert_eq!(child_string(0x40), "spawnkid args one \"two words\"");
    assert_eq!(child_string(0x24), "C:\\CORPUS\\");
    assert_eq!(child_string(0x30), SEARCH);
    assert_eq!(child_string(0x70), "C:\\CORPUS\\SPAWNKID.EXE");
    assert_eq!(
        [0x18, 0x1C, 0x20].map(|at| child_dword(PARAMETERS + at)),
        [3, 7, 0xB],
        "the caller's standard handles"
    );
    let thread = CREATED.with(|created| created.borrow()[0].clone());
    assert_eq!(
        (
            thread.process,
            thread.access,
            thread.inherit,
            thread.suspended
        ),
        (CHILD_PROCESS, 0x001F_03FF, false, true)
    );
    assert_eq!(
        [context::EIP, context::EAX, context::EBX, context::ESP].map(|at| thread.context[at]),
        [
            PROCESS_START_THUNK,
            CHILD_ENTRY,
            CHILD_PEB as u32,
            0x0012_FFFC
        ]
    );
    assert_eq!(
        (
            thread.stack.stack_base,
            thread.stack.stack_limit,
            thread.stack.allocation_base
        ),
        (0x0013_0000, 0x0012_E000, 0x0003_0000)
    );
    THREADS.with(|threads| {
        let threads = threads.borrow();
        let created = threads.iter().find(|(handle, _)| *handle == CREATED_THREAD);
        assert_eq!(created.unwrap().1.suspend_count, 0, "resumed");
    });
    assert_eq!(closed(), [HANDLE, HANDLE], "the file, then the section");
    assert_eq!(
        PARAMETERS_DESTROYED.with(|destroyed| destroyed.borrow().len()),
        1
    );
}

/// The strings' room in the block the last creation made (as `rtl::params` lays it out).
fn made_room() -> usize {
    let made = made().pop().unwrap();
    let units = |text: &str| text.encode_utf16().count() * 2;
    let room = |bytes: usize, minimum: usize| (bytes + 2).max(minimum).next_multiple_of(4);
    room(
        units(&made.current_directory.unwrap_or("C:\\CORPUS\\".into())),
        520,
    ) + room(units(&made.dll_path.unwrap()), 0)
        + room(units(&made.image_path_name), 0)
        + room(units(&made.command_line.unwrap()), 0)
        + made.window_title.map_or(0, |title| room(units(&title), 0))
        + made
            .desktop_info
            .map_or(0, |desktop| room(units(&desktop), 0))
        + made.shell_info.map_or(0, |shell| room(units(&shell), 0))
        + made.runtime_data.map_or(0, |data| room(data.len(), 0))
}

/// The child's image path and command line, as the last creation wrote them.
fn child_names() -> (String, String) {
    (child_string(0x38), child_string(0x40))
}

/// A command line alone: its first name searched for as SearchPath's default search looks (the
/// program's directory, the current directory, the system directories, the Windows directory,
/// PATH), `.exe` added; the first place that has it wins; the command line goes as given, and a
/// search that finds the program leaves the last error alone.
///
/// Pins: kernel32.CreateProcessW
#[test]
fn a_command_line_alone_searches_for_its_program() {
    setup();
    existing(&["C:\\TOOLS\\KID.EXE"]);
    let (created, error, _) = run("kid args x");
    assert_eq!((created, error), (1, UNTOUCHED));
    let places: Vec<String> = SEARCH
        .split(';')
        .map(|place| format!("{place}\\kid.exe"))
        .collect();
    EXISTENCE_ASKED.with(|asked| assert_eq!(*asked.borrow(), places));
    assert_eq!(
        child_names(),
        ("C:\\TOOLS\\kid.exe".into(), "kid args x".into())
    );

    setup();
    CURRENT_DIRECTORY
        .with(|current| *current.borrow_mut() = "C:\\CORPUS\\SUB\\".encode_utf16().collect());
    existing(&["C:\\CORPUS\\SUB\\KID.EXE", "C:\\TOOLS\\KID.EXE"]);
    run("kid where");
    assert_eq!(
        child_names().0,
        "C:\\CORPUS\\SUB\\kid.exe",
        "the current directory before PATH"
    );

    setup();
    CURRENT_DIRECTORY
        .with(|current| *current.borrow_mut() = "C:\\CORPUS\\SUB\\".encode_utf16().collect());
    existing(&["C:\\CORPUS\\SUB\\KID.EXE", "C:\\CORPUS\\KID.EXE"]);
    run("kid where");
    assert_eq!(
        child_names().0,
        "C:\\CORPUS\\kid.exe",
        "the program's directory first"
    );

    setup();
    existing(&["C:\\CORPUS\\SUB\\KIDCOPY.EXE"]);
    run("sub\\kidcopy where");
    assert_eq!(
        child_names().0,
        "C:\\CORPUS\\sub\\kidcopy.exe",
        "a relative path under each directory"
    );

    setup();
    existing(&["C:\\CORPUS\\NOTEXE.TXT"]);
    run("notexe.txt args");
    assert_eq!(
        child_names().0,
        "C:\\CORPUS\\notexe.txt",
        "an extension kept"
    );
}

/// An unquoted name with spaces is tried at each space in turn: the whole found last gets quoted
/// in the child's command line (the searches' misses leave ERROR_FILE_NOT_FOUND, as the capture's
/// "ret=1 err=2"); a shorter name found first runs, the rest its arguments. A quoted name is the
/// text between the quotes, the command line kept.
///
/// Pins: kernel32.CreateProcessW
#[test]
fn an_unquoted_name_with_spaces_runs_the_first_that_exists() {
    setup();
    existing(&["C:\\CORPUS\\WITH SPACE\\KID COPY.EXE"]);
    let (created, error, _) = run("with space\\kid copy.exe");
    assert_eq!((created, error), (1, 2));
    assert_eq!(
        child_names(),
        (
            "C:\\CORPUS\\with space\\kid copy.exe".into(),
            "\"with space\\kid copy.exe\"".into()
        )
    );
    let asked = EXISTENCE_ASKED.with(|asked| asked.borrow().clone());
    assert_eq!(asked[0], "C:\\CORPUS\\with.exe");
    assert_eq!(asked[6], "C:\\CORPUS\\with space\\kid.exe");
    assert_eq!(asked[12], "C:\\CORPUS\\with space\\kid copy.exe");

    setup();
    existing(&["C:\\CORPUS\\WITH SPACE\\KID COPY.EXE"]);
    run("with space\\kid copy.exe args a");
    assert_eq!(
        child_names().1,
        "\"with space\\kid copy.exe\" args a",
        "the arguments after the quoted name"
    );

    setup();
    existing(&[
        "C:\\CORPUS\\WITH SPACE\\KID COPY.EXE",
        "C:\\CORPUS\\WITH.EXE",
    ]);
    let (created, error, _) = run("with space\\kid copy.exe");
    assert_eq!((created, error), (1, UNTOUCHED));
    assert_eq!(
        child_names(),
        (
            "C:\\CORPUS\\with.exe".into(),
            "with space\\kid copy.exe".into()
        )
    );

    setup();
    existing(&[
        "C:\\CORPUS\\WITH SPACE\\KID COPY.EXE",
        "C:\\CORPUS\\WITH.EXE",
    ]);
    let (created, error, _) = run("\"with space\\kid copy.exe\" args a");
    assert_eq!((created, error), (1, UNTOUCHED));
    assert_eq!(
        child_names(),
        (
            "C:\\CORPUS\\with space\\kid copy.exe".into(),
            "\"with space\\kid copy.exe\" args a".into()
        )
    );
}

/// The application name is taken as given: no search and no extension added, made full against
/// the current directory; without a command line the child's is the name quoted.
///
/// Pins: kernel32.CreateProcessW
#[test]
fn the_application_name_is_not_searched_for() {
    setup();
    let (created, _, _) = create(
        Some("spawnkid.exe"),
        None,
        0,
        core::ptr::null(),
        None,
        &startup(),
    );
    assert_eq!(created, 1);
    assert_eq!(
        child_names(),
        ("C:\\CORPUS\\spawnkid.exe".into(), "\"spawnkid.exe\"".into())
    );
    EXISTENCE_ASKED.with(|asked| assert!(asked.borrow().is_empty()));

    setup();
    FAIL_NEXT.with(|next| next.set(0xC000_0034));
    let (created, error, _) = create(
        Some("spawnkid"),
        Some("spawnkid args"),
        0,
        core::ptr::null(),
        None,
        &startup(),
    );
    assert_eq!((created, error), (0, 2));
    assert!(image_open().3.ends_with("C:\\CORPUS\\spawnkid"));
    assert!(CHILD.with(|child| child.borrow().is_none()));
}

/// What cannot run, with Windows 2000's errors: a missing file (2) or directory (3), a directory
/// (5), a file that is no image or an empty one (193: the section refuses it), a DLL, an image for
/// another machine or subsystem (193: the section's description refuses it, the section closed);
/// a name found nowhere, an empty command line and an empty quoted name (2). Nothing is made.
///
/// Pins: kernel32.CreateProcessW
#[test]
fn what_cannot_run_fails_as_on_windows_2000() {
    let named = |status: u32| {
        setup();
        FAIL_NEXT.with(|next| next.set(status));
        create(
            Some("SCRATCH\\kidnone.exe"),
            Some("kidnone"),
            0,
            core::ptr::null(),
            None,
            &startup(),
        )
        .1
    };
    assert_eq!(named(0xC000_0034), 2, "a missing file");
    assert_eq!(named(0xC000_003A), 3, "a missing directory");
    assert_eq!(named(0xC000_00BA), 5, "a directory");
    for status in [0xC000_007B, 0xC000_012F, 0xC000_011E, 0xC000_0020] {
        setup();
        fail("NtCreateSection", status);
        let (created, error, _) = create(
            Some("notexe.txt"),
            None,
            0,
            core::ptr::null(),
            None,
            &startup(),
        );
        assert_eq!((created, error), (0, 193), "{status:#x}");
        assert_eq!(closed(), [HANDLE], "the file");
    }
    for (characteristics, machine, subsystem) in [
        (0x2102, 0x014C, 3), // a DLL
        (0x0102, 0x0184, 3), // another machine
        (0x0102, 0x014C, 7), // the POSIX subsystem
    ] {
        setup();
        SECTION_IMAGE.with(|words| {
            let mut words = words.borrow_mut();
            *words = children::image(characteristics, subsystem);
            words[8] = machine | 1 << 16;
        });
        let (created, error, _) = create(
            Some("C:\\WINNT\\system32\\kernel32.dll"),
            Some("kernel32"),
            0,
            core::ptr::null(),
            None,
            &startup(),
        );
        assert_eq!((created, error), (0, 193));
        assert_eq!(closed(), [HANDLE, HANDLE], "the file and the section");
        assert!(CHILD.with(|child| child.borrow().is_none()));
    }
    for line in ["kidnone args", "", "\"\" args", "\"C:\\NODIR\\X.EXE\" args"] {
        setup();
        let (created, error, _) = run(line);
        assert_eq!((created, error), (0, 2), "{line:?}");
        assert!(calls().is_empty(), "nothing opened");
    }
}

/// No application name and no command line: a fault for the caller (the export raises
/// STATUS_ACCESS_VIOLATION in it), as Windows 2000's reads through the missing command line;
/// nothing is looked for. CreateProcessW's work is asked directly: the stand-in's raise is a
/// panic, which cannot cross the export.
///
/// Pins: kernel32.CreateProcessW
#[test]
fn no_name_at_all_faults_the_caller() {
    setup();
    let created = crate::create::create_process(&crate::create::Request {
        application_name: None,
        command_line: None,
        process_attributes: None,
        thread_attributes: None,
        inherit_handles: true,
        flags: 0,
        environment: crate::create::Environment::Inherited,
        current_directory: None,
        startup: crate::create::Startup::default(),
    });
    assert_eq!(created, Err(crate::create::Failure::Fault(0xC000_0005)));
    assert!(calls().is_empty());
}

/// lpCurrentDirectory: made full and handed to the child's parameters; one that is not a
/// directory, or does not exist, is ERROR_DIRECTORY before anything is opened; the program is
/// still searched for from the caller's own current directory.
///
/// Pins: kernel32.CreateProcessW
#[test]
fn the_current_directory_asked_for_must_be_a_directory() {
    setup();
    FILE.with(|file| file.borrow_mut().attributes = 0x10);
    existing(&["C:\\CORPUS\\SPAWNKID.EXE"]);
    let (created, _, _) = create(
        None,
        Some("spawnkid where"),
        0,
        core::ptr::null(),
        Some("SCRATCH\\sub"),
        &startup(),
    );
    assert_eq!(created, 1);
    assert_eq!(
        made()[0].current_directory.as_deref(),
        Some("C:\\CORPUS\\SCRATCH\\sub")
    );
    assert_eq!(child_string(0x24), "C:\\CORPUS\\SCRATCH\\sub");

    for (attributes, failure) in [(0x20, 0), (0x10, 0xC000_0034)] {
        setup();
        FILE.with(|file| file.borrow_mut().attributes = attributes);
        FAIL_NEXT.with(|next| next.set(failure));
        existing(&["C:\\CORPUS\\SPAWNKID.EXE"]);
        let (created, error, _) = create(
            None,
            Some("spawnkid where"),
            0,
            core::ptr::null(),
            Some("C:\\CORPUS\\afile.txt"),
            &startup(),
        );
        assert_eq!((created, error), (0, 267));
        assert_eq!(calls().len(), 1, "the attributes asked, nothing opened");
    }

    setup();
    FILE.with(|file| file.borrow_mut().attributes = 0x10);
    existing(&["C:\\CORPUS\\SUB\\KIDCOPY.EXE"]);
    let (created, error, _) = create(
        None,
        Some("kidcopy where"),
        0,
        core::ptr::null(),
        Some("C:\\CORPUS\\SUB"),
        &startup(),
    );
    assert_eq!((created, error), (0, 2), "not searched for there");
}

/// The environment the child gets, written at 0x00010000: an ANSI block converted through the
/// ANSI code page, its order kept; a UTF-16 one with CREATE_UNICODE_ENVIRONMENT as it is; an empty
/// one its two NULs; none the caller's own.
///
/// Pins: kernel32.CreateProcessW
#[test]
fn the_environment_block_is_written_into_the_child() {
    let with = |block: *const u8, flags: u32| {
        setup();
        existing(&["C:\\CORPUS\\SPAWNKID.EXE"]);
        let (created, _, _) = create(
            None,
            Some("spawnkid envall"),
            flags,
            block,
            None,
            &startup(),
        );
        assert_eq!(created, 1);
        assert_eq!(child_dword(PARAMETERS + 0x48), ENVIRONMENT_AT as u32);
    };
    let ansi = b"ZED=last letter, first\0ALPHA=\x80\0\0";
    with(ansi.as_ptr(), 0);
    assert_eq!(
        child_text(ENVIRONMENT_AT, 32),
        "ZED=last letter, first\0ALPHA=\u{20AC}\0\0"
    );
    let unicode = wide("F2KW=wide\0F2KX=also wide\0");
    with(unicode.as_ptr().cast(), 0x400);
    assert_eq!(
        child_text(ENVIRONMENT_AT, 26),
        "F2KW=wide\0F2KX=also wide\0\0"
    );
    with(b"\0\0".as_ptr(), 0);
    assert_eq!(child_bytes(ENVIRONMENT_AT, 6), [0; 6]);
    with(core::ptr::null(), 0);
    assert_eq!(
        child_text(ENVIRONMENT_AT, OWN_ENVIRONMENT.len()),
        OWN_ENVIRONMENT
    );
}

/// STARTUPINFO goes into the child's parameters: with STARTF_USESTDHANDLES its standard handles
/// (whatever bInheritHandles says), the flags, the show-window value, the window's values, the
/// title, desktop, shell information (lpReserved) and the C runtime's block; a GUI program without
/// STARTF_USESTDHANDLES gets no standard handles and no console.
///
/// Pins: kernel32.CreateProcessW
#[test]
fn the_startup_information_reaches_the_child() {
    setup();
    existing(&["C:\\CORPUS\\SPAWNKID.EXE"]);
    let (title, desktop, shell) = (wide("a title"), wide("WinSta0\\Default"), wide("shell"));
    let runtime = [2u8, 0, 0, 0, 0x01, 0x41, 0x44, 0, 0, 0, 0x48, 0, 0, 0];
    let info = StartupInfo {
        reserved: shell.as_ptr(),
        desktop: desktop.as_ptr(),
        title: title.as_ptr(),
        values: [1, 2, 3, 4, 5, 6, 7],
        flags: 0x100,
        show_window: 5,
        reserved2_length: runtime.len() as u16,
        reserved2: runtime.as_ptr(),
        standard_input: 0x44,
        standard_output: 0x48,
        standard_error: 0x4C,
        ..startup()
    };
    let (created, _, _) = create(
        None,
        Some("spawnkid out"),
        0,
        core::ptr::null(),
        None,
        &info,
    );
    assert_eq!(created, 1);
    assert_eq!(
        [0x18, 0x1C, 0x20].map(|at| child_dword(PARAMETERS + at)),
        [0x44, 0x48, 0x4C]
    );
    assert_eq!(
        (0x4C..0x70)
            .step_by(4)
            .map(|at| child_dword(PARAMETERS + at))
            .collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6, 7, 0x100, 5]
    );
    assert_eq!(child_string(0x70), "a title");
    assert_eq!(child_string(0x78), "WinSta0\\Default");
    assert_eq!(child_string(0x80), "shell");
    let length = child_dword(PARAMETERS + 0x88) & 0xFFFF;
    let buffer = PARAMETERS + child_dword(PARAMETERS + 0x8C) as usize;
    assert_eq!(child_bytes(buffer, length as usize), runtime);

    setup();
    existing(&["C:\\CORPUS\\SPAWNKID.EXE"]);
    SECTION_IMAGE.with(|words| *words.borrow_mut() = children::image(0x0102, 2));
    run("spawnkid gui");
    assert_eq!(
        [0x10, 0x18, 0x1C, 0x20].map(|at| child_dword(PARAMETERS + at)),
        [0; 4]
    );
}

/// bInheritHandles reaches NtCreateProcess; the SECURITY_ATTRIBUTES make the process's and the
/// thread's handles inheritable; a priority class flag is the child's class, the caller's
/// hard-error mode its own unless CREATE_DEFAULT_ERROR_MODE; CREATE_SUSPENDED leaves the thread
/// suspended.
///
/// Pins: kernel32.CreateProcessW
#[test]
fn the_flags_and_attributes_shape_the_child() {
    setup();
    existing(&["C:\\CORPUS\\SPAWNKID.EXE"]);
    HARD_ERROR_MODE.with(|mode| mode.set(0));
    let line = wide("spawnkid args");
    let mut line = line.clone();
    let inheritable = crate::base::SecurityAttributes {
        length: 12,
        security_descriptor: core::ptr::null(),
        inherit_handle: 1,
    };
    let mut information = ProcessInformation::default();
    let created = unsafe {
        create_process_w(
            core::ptr::null(),
            line.as_mut_ptr(),
            &inheritable,
            &inheritable,
            0,
            0x0000_0040 | 0x0000_0004,
            core::ptr::null(),
            core::ptr::null(),
            &startup(),
            &mut information,
        )
    };
    assert_eq!(created, 1);
    with_child(|child| {
        assert_eq!((child.inherit_handles, child.inheritable), (false, true));
        assert_eq!(
            child.information,
            [(18, vec![0, 1]), (12, vec![0, 0, 0, 0])]
        );
    });
    assert!(CREATED.with(|created| created.borrow()[0].inherit));
    THREADS.with(|threads| {
        let threads = threads.borrow();
        let created = threads.iter().find(|(handle, _)| *handle == CREATED_THREAD);
        assert_eq!(created.unwrap().1.suspend_count, 1, "left suspended");
    });

    setup();
    existing(&["C:\\CORPUS\\SPAWNKID.EXE"]);
    HARD_ERROR_MODE.with(|mode| mode.set(0));
    create(
        None,
        Some("spawnkid args"),
        0x0400_0000,
        core::ptr::null(),
        None,
        &startup(),
    );
    with_child(|child| assert_eq!(child.information[1], (12, vec![1, 0, 0, 0])));
}

/// The child's ConsoleFlags: the caller's own (its ignoring of Ctrl+C is inherited), set under
/// CREATE_NEW_PROCESS_GROUP.
///
/// Pins: kernel32.CreateProcessW
#[test]
fn the_ignoring_of_ctrl_c_is_inherited() {
    for (own, flags, child) in [
        (0, 0, 0),
        (1, 0, 1),
        (0, 0x0000_0200, 1),
        (1, 0x0000_0200, 1),
    ] {
        setup();
        existing(&["C:\\CORPUS\\SPAWNKID.EXE"]);
        crate::base::update_console_flags(|_| own);
        create(
            None,
            Some("spawnkid args"),
            flags,
            core::ptr::null(),
            None,
            &startup(),
        );
        assert_eq!(
            child_dword(PARAMETERS + 0x14),
            child,
            "the caller's {own}, the flags {flags:#x}"
        );
    }
    crate::base::update_console_flags(|_| 0);
}

/// Every failure undoes what was made: NtCreateProcess refused (its error; the file and section
/// closed, nothing to end); the environment's write refused, or the first thread's creation (the
/// child ended with the status and its handle closed, the parameters block freed).
///
/// Pins: kernel32.CreateProcessW
#[test]
fn a_failure_undoes_what_was_made() {
    setup();
    existing(&["C:\\CORPUS\\SPAWNKID.EXE"]);
    fail("NtCreateProcess", 0xC000_0002);
    let (created, error, _) = run("spawnkid");
    assert_eq!((created, error), (0, 1));
    assert_eq!(closed(), [HANDLE, HANDLE]);
    TERMINATED.with(|terminated| assert!(terminated.borrow().is_empty()));

    setup();
    existing(&["C:\\CORPUS\\SPAWNKID.EXE"]);
    fail("NtWriteVirtualMemory", 0xC000_0005);
    let (created, error, _) = run("spawnkid");
    assert_eq!((created, error), (0, 998));
    assert_eq!(closed(), [HANDLE, HANDLE, CHILD_PROCESS]);
    TERMINATED.with(|terminated| {
        assert_eq!(
            *terminated.borrow(),
            [("process", CHILD_PROCESS, 0xC000_0005)]
        )
    });
    assert!(made().is_empty(), "the environment goes first");

    setup();
    existing(&["C:\\CORPUS\\SPAWNKID.EXE"]);
    CREATE_FAILS.with(|fails| fails.set(0xC000_0017));
    let (created, error, _) = run("spawnkid");
    assert_eq!((created, error), (0, 8));
    assert_eq!(closed(), [HANDLE, HANDLE, CHILD_PROCESS]);
    TERMINATED.with(|terminated| {
        assert_eq!(
            *terminated.borrow(),
            [("process", CHILD_PROCESS, 0xC000_0017)]
        )
    });
    assert_eq!(made().len(), 1);
    assert_eq!(
        PARAMETERS_DESTROYED.with(|destroyed| destroyed.borrow().len()),
        1
    );
}

/// DETACHED_PROCESS, CREATE_NEW_CONSOLE and the debugging flags take the stub path: logged, FALSE
/// with ERROR_CALL_NOT_IMPLEMENTED, nothing looked for or made.
///
/// Pins: kernel32.CreateProcessW, kernel32.CreateProcessA
#[test]
fn a_detached_process_or_a_new_console_is_not_implemented() {
    for flags in [0x8, 0x10, 0x1, 0x2] {
        setup();
        let (created, error, _) = create(
            None,
            Some("spawnkid exit 12"),
            flags,
            core::ptr::null(),
            None,
            &startup(),
        );
        assert_eq!((created, error), (0, 120));
        let prints = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
        assert!(
            prints[0].starts_with("stub kernel32.CreateProcessW(lpApplicationName=NULL, ")
                && prints[0].contains(&format!("dwCreationFlags={flags:#x}"))
                && prints[0].ends_with(": not yet implemented\n"),
            "{prints:?}"
        );
        assert!(calls().is_empty());
    }
    setup();
    let mut line = *b"spawnkid exit 13\0";
    let mut information = ProcessInformation::default();
    let created = unsafe {
        create_process_a(
            core::ptr::null(),
            line.as_mut_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            1,
            0x10,
            core::ptr::null(),
            core::ptr::null(),
            &startup(),
            &mut information,
        )
    };
    assert_eq!((created, last_error()), (0, 120));
    let prints = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
    assert!(
        prints[0].starts_with(
            "stub kernel32.CreateProcessA(lpApplicationName=NULL, \
             lpCommandLine=\"spawnkid exit 13\""
        ),
        "{prints:?}"
    );
}

/// CreateProcessA converts its strings through the ANSI code page (the euro sign is 0x80) and does
/// CreateProcessW's work.
///
/// Pins: kernel32.CreateProcessA
#[test]
fn create_process_a_converts_and_creates() {
    setup();
    existing(&["C:\\CORPUS\\SPAWNKID.EXE"]);
    FILE.with(|file| file.borrow_mut().attributes = 0x10);
    let mut line = *b"spawnkid args \x80\0";
    let title = *b"t\x80\0";
    let info = StartupInfo {
        title: title.as_ptr(),
        ..startup()
    };
    let mut information = ProcessInformation::default();
    let created = unsafe {
        create_process_a(
            core::ptr::null(),
            line.as_mut_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            1,
            0,
            core::ptr::null(),
            b"SCRATCH\0".as_ptr(),
            &info,
            &mut information,
        )
    };
    assert_eq!((created, information.process), (1, CHILD_PROCESS));
    let made = made().pop().unwrap();
    assert_eq!(made.command_line.as_deref(), Some("spawnkid args \u{20AC}"));
    assert_eq!(made.window_title.as_deref(), Some("t\u{20AC}"));
    assert_eq!(
        made.current_directory.as_deref(),
        Some("C:\\CORPUS\\SCRATCH")
    );
    assert_eq!(made.image_path_name, "C:\\CORPUS\\spawnkid.exe");
}

/// A child made, as the other scenarios make it.
fn a_child() -> ProcessInformation {
    setup();
    existing(&["C:\\CORPUS\\SPAWNKID.EXE"]);
    let (created, _, information) = run("spawnkid wait");
    assert_eq!(created, 1);
    information
}

/// OpenProcess asks NtOpenProcess for the id (no thread), the handle inheritable when asked; an
/// id naming no process, zero included, is ERROR_INVALID_PARAMETER.
///
/// Pins: kernel32.OpenProcess
#[test]
fn open_process_opens_by_id() {
    a_child();
    assert_eq!(
        open_process(0x0010_0400, 1, CHILD_ID as u32),
        OPENED_PROCESS
    );
    assert_eq!(open_process(0x0400, 0, 0), 0);
    assert_eq!(last_error(), 87);
    OPENED.with(|opened| {
        assert_eq!(
            *opened.borrow(),
            [(0x0010_0400, 2, CHILD_ID), (0x0400, 0, 0)]
        )
    });
}

/// GetExitCodeProcess answers STILL_ACTIVE while the child runs, its exit status once
/// TerminateProcess ended it; ending it again is refused (ERROR_ACCESS_DENIED); a handle naming
/// nothing is ERROR_INVALID_HANDLE; the caller's own process is still active.
///
/// Pins: kernel32.GetExitCodeProcess, kernel32.TerminateProcess
#[test]
fn exit_codes_and_termination_of_a_child() {
    let information = a_child();
    let mut code = 0xF2F2;
    assert_eq!(
        unsafe { get_exit_code_process(information.process, &mut code) },
        1
    );
    assert_eq!(code, 259);
    assert_eq!(terminate_process(information.process, 42), 1);
    assert_eq!(
        unsafe { get_exit_code_process(OPENED_PROCESS, &mut code) },
        1
    );
    assert_eq!(code, 42);
    assert_eq!(terminate_process(information.process, 43), 0);
    assert_eq!(last_error(), 5);
    assert_eq!(unsafe { get_exit_code_process(0x99, &mut code) }, 0);
    assert_eq!(last_error(), 6);
    assert_eq!(
        unsafe { get_exit_code_process(CURRENT_PROCESS, &mut code) },
        1
    );
    assert_eq!(code, 259);
}

/// ReadProcessMemory: the child's bytes, the count written; past what the child maps a partial
/// copy (ERROR_PARTIAL_COPY, the count the service's); no count asked for is fine; the caller's
/// own memory through its pseudo-handle.
///
/// Pins: kernel32.ReadProcessMemory
#[test]
fn read_process_memory_reads_the_child() {
    a_child();
    let (mut value, mut count) = (0u32, 0xF2F2u32);
    let read = unsafe {
        read_process_memory(
            CHILD_PROCESS,
            CHILD_PEB + 0x10,
            (&mut value as *mut u32).cast(),
            4,
            &mut count,
        )
    };
    assert_eq!((read, value, count), (1, PARAMETERS as u32, 4));
    let mut bytes = [0u8; 16];
    let across = CHILD_IMAGE_BASE + CHILD_IMAGE_SIZE - 8;
    let read =
        unsafe { read_process_memory(CHILD_PROCESS, across, bytes.as_mut_ptr(), 16, &mut count) };
    assert_eq!((read, count, last_error()), (0, 0, 299));
    let read = unsafe {
        read_process_memory(
            CHILD_PROCESS,
            CHILD_IMAGE_BASE,
            bytes.as_mut_ptr(),
            2,
            core::ptr::null_mut(),
        )
    };
    assert_eq!((read, &bytes[..2]), (1, &b"MZ"[..]));
    let local = 0x5A5A_5A5Au32;
    let mut copy = 0u32;
    let read = unsafe {
        read_process_memory(
            CURRENT_PROCESS,
            &local as *const u32 as usize,
            (&mut copy as *mut u32).cast(),
            4,
            &mut count,
        )
    };
    assert_eq!((read, copy, count), (1, local, 4));
}

/// WriteProcessMemory makes the range writable first: read-only pages get their protection back
/// and the call fails with ERROR_NOACCESS, nothing written and the count untouched; writable pages
/// get theirs back, then the bytes are written; code pages are written under the temporary
/// protection, then get theirs back; each write is followed by the instruction cache's flush over
/// the range; a range not mapped is the protection's refusal (487), nothing flushed.
///
/// Pins: kernel32.WriteProcessMemory
#[test]
fn write_process_memory_writes_what_may_be_written() {
    a_child();
    child_vm();
    let mark = 0x4B32_4632u32;
    let source = (&mark as *const u32).cast::<u8>();
    let mut count = 0xF2F2u32;
    let header = CHILD_IMAGE_BASE + 0x28;
    let written = unsafe { write_process_memory(CHILD_PROCESS, header, source, 4, &mut count) };
    assert_eq!((written, last_error(), count), (0, 998, 0xF2F2));
    assert_eq!(child_dword(header), 0);
    assert_eq!(
        child_vm(),
        [
            ("protect", CHILD_IMAGE_BASE, 0x1000, 0x40),
            ("protect", CHILD_IMAGE_BASE, 0x1000, 0x02)
        ]
    );

    let slot = CHILD_PEB + 0x100;
    let written = unsafe { write_process_memory(CHILD_PROCESS, slot, source, 4, &mut count) };
    assert_eq!((written, count, child_dword(slot)), (1, 4, mark));
    assert_eq!(
        child_vm(),
        [
            ("protect", CHILD_PEB, 0x1000, 0x40),
            ("protect", CHILD_PEB, 0x1000, 0x04),
            ("flush", slot, 4, 0)
        ]
    );

    with_child(|child| child.regions[0].protect = 0x20);
    let code = CHILD_IMAGE_BASE + 0x1000;
    let written =
        unsafe { write_process_memory(CHILD_PROCESS, code, source, 4, core::ptr::null_mut()) };
    assert_eq!((written, child_dword(code)), (1, mark));
    assert_eq!(with_child(|child| child.regions[0].protect), 0x20);
    assert_eq!(child_vm().last(), Some(&("flush", code, 4, 0)));

    count = 0xF2F2;
    let written = unsafe { write_process_memory(CHILD_PROCESS, 0, source, 4, &mut count) };
    assert_eq!((written, last_error(), count), (0, 487, 0xF2F2));
    assert!(!child_vm().iter().any(|call| call.0 == "flush"));
}
