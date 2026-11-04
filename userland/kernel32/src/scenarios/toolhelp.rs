//! ToolHelp: CreateToolhelp32Snapshot over the stand-in process listing
//! ([`crate::nt::toolhelp`]: NtQuerySystemInformation's records as the kernel writes them, and
//! sections of the paging file backed by memory), walked with Process32First/Next, their W forms
//! and Thread32First/Next. The toolhelp fixture is the contract on the machine; these pin what
//! kernel32 decides: the section a snapshot is, the entries' fields, the walks' ends and the
//! errors it sets, as the fixture's capture has them.

use rtl::pod::Pod;

use super::last_error;
use crate::error::{
    ERROR_BAD_LENGTH,
    ERROR_INVALID_HANDLE,
    ERROR_INVALID_PARAMETER,
    ERROR_NO_MORE_FILES,
};
use crate::nt::host::{LAST_SECTION, LAST_VM};
use crate::nt::toolhelp::{install, ListedProcess, ListedThread};
use crate::toolhelp::{
    create_toolhelp32_snapshot,
    process32_first,
    process32_first_w,
    process32_next,
    process32_next_w,
    thread32_first,
    thread32_next,
    ProcessEntry32,
    ProcessEntry32W,
    ThreadEntry32,
    TH32CS_SNAPMODULE,
    TH32CS_SNAPPROCESS,
    TH32CS_SNAPTHREAD,
};

const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;

/// The machine the scenarios list: the idle process, a program and its child.
fn machine() -> Vec<ListedProcess> {
    vec![
        ListedProcess::idle(),
        ListedProcess {
            id: 24,
            parent_id: 0,
            base_priority: 8,
            name: "sched.exe",
            threads: vec![ListedThread::new(28, 8), ListedThread::new(36, 9)],
        },
        ListedProcess {
            id: 32,
            parent_id: 24,
            base_priority: 8,
            name: "ps.exe",
            threads: vec![ListedThread::new(40, 8)],
        },
    ]
}

/// A PROCESSENTRY32W whose dwSize the caller set.
fn wide_entry() -> ProcessEntry32W {
    let mut entry = ProcessEntry32W::zeroed();
    entry.size = size_of::<ProcessEntry32W>() as u32;
    entry
}

fn name(units: &[u16]) -> String {
    let length = units.iter().position(|&unit| unit == 0).unwrap();
    String::from_utf16(&units[..length]).unwrap()
}

/// Every process the W walk answers: id, parent, threads, base priority, name; then the walk's
/// last error past its end.
fn walk_w(snapshot: u32) -> (Vec<(u32, u32, u32, i32, String)>, u32) {
    let mut walked = Vec::new();
    let mut entry = wide_entry();
    let mut more = unsafe { process32_first_w(snapshot, &mut entry) };
    while more != 0 {
        walked.push((
            entry.process_id,
            entry.parent_process_id,
            entry.threads,
            entry.pri_class_base,
            name(&entry.exe_file),
        ));
        more = unsafe { process32_next_w(snapshot, &mut entry) };
    }
    (walked, last_error())
}

/// A snapshot of the processes is a section of the paging file (committed, read-write, granted
/// the capture's 0x000F0007) of its header and entries, the threads' too; the W walk answers every
/// listed process in order — the idle process as `[System Process]` — then FALSE with
/// ERROR_NO_MORE_FILES, and a First starts it over.
///
/// Pins: kernel32.CreateToolhelp32Snapshot, kernel32.Process32FirstW, kernel32.Process32NextW
#[test]
fn a_process_snapshot_walks_every_process() {
    install(machine());
    let snapshot = create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0);
    assert_ne!(snapshot, INVALID_HANDLE_VALUE);
    let (access, protect, allocation, file, maximum) =
        LAST_SECTION.with(|cell| cell.get()).unwrap();
    assert_eq!(
        (access, protect, allocation, file),
        (0x000F_0007, 0x04, 0x0800_0000, 0),
        "the map and query rights, PAGE_READWRITE, SEC_COMMIT, the paging file"
    );
    assert_eq!(
        maximum,
        Some(16 + 3 * 556 + 4 * 28),
        "the header, three process entries and four thread entries"
    );
    let (walked, error) = walk_w(snapshot);
    assert_eq!(
        walked,
        [
            (0, 0, 1, 0, "[System Process]".to_string()),
            (24, 0, 2, 8, "sched.exe".to_string()),
            (32, 24, 1, 8, "ps.exe".to_string()),
        ]
    );
    assert_eq!(error, ERROR_NO_MORE_FILES);
    let (again, _) = walk_w(snapshot);
    assert_eq!(again.len(), 3, "a First starts the walk over");
    assert_eq!(
        LAST_VM.with(|cell| cell.get()).map(|(_, size, _)| size),
        Some(0),
        "each call unmaps its view"
    );
}

/// The ANSI walk answers the same entries, their names in the ANSI code page, dwSize as the caller
/// set it.
///
/// Pins: kernel32.Process32First, kernel32.Process32Next
#[test]
fn the_ansi_walk_narrows_the_names() {
    install(machine());
    let snapshot = create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0);
    let mut entry = ProcessEntry32::zeroed();
    entry.size = size_of::<ProcessEntry32>() as u32;
    let mut names = Vec::new();
    let mut more = unsafe { process32_first(snapshot, &mut entry) };
    while more != 0 {
        assert_eq!(entry.size, 296);
        let length = entry.exe_file.iter().position(|&byte| byte == 0).unwrap();
        names.push(String::from_utf8(entry.exe_file[..length].to_vec()).unwrap());
        more = unsafe { process32_next(snapshot, &mut entry) };
    }
    assert_eq!(names, ["[System Process]", "sched.exe", "ps.exe"]);
    assert_eq!(last_error(), ERROR_NO_MORE_FILES);
}

/// A thread snapshot lists every thread of every process with its owner and base priority, and
/// the processes too, as the capture shows: the process walk finds them.
///
/// Pins: kernel32.Thread32First, kernel32.Thread32Next
#[test]
fn a_thread_snapshot_walks_every_thread() {
    install(machine());
    let snapshot = create_toolhelp32_snapshot(TH32CS_SNAPTHREAD, 0);
    let mut entry = ThreadEntry32 {
        size: 28,
        ..Default::default()
    };
    let mut threads = Vec::new();
    let mut more = unsafe { thread32_first(snapshot, &mut entry) };
    while more != 0 {
        threads.push((entry.thread_id, entry.owner_process_id, entry.base_pri));
        assert_eq!((entry.usage, entry.delta_pri, entry.flags), (0, 0, 0));
        more = unsafe { thread32_next(snapshot, &mut entry) };
    }
    assert_eq!(threads, [(0, 0, 0), (28, 24, 8), (36, 24, 9), (40, 32, 8)]);
    assert_eq!(last_error(), ERROR_NO_MORE_FILES);
    let mut process = wide_entry();
    assert_eq!(unsafe { process32_first_w(snapshot, &mut process) }, 1);
    assert_eq!(process.process_id, 0);
}

/// A snapshot of neither processes nor threads is a handle whose walks find nothing:
/// ERROR_NO_MORE_FILES.
///
/// Pins: kernel32.CreateToolhelp32Snapshot, kernel32.Process32FirstW, kernel32.Thread32First
#[test]
fn a_snapshot_of_no_list_walks_nothing() {
    install(machine());
    let snapshot = create_toolhelp32_snapshot(0, 0);
    assert_ne!(snapshot, INVALID_HANDLE_VALUE);
    let mut process = wide_entry();
    assert_eq!(unsafe { process32_first_w(snapshot, &mut process) }, 0);
    assert_eq!(last_error(), ERROR_NO_MORE_FILES);
    let mut thread = ThreadEntry32 {
        size: 28,
        ..Default::default()
    };
    assert_eq!(unsafe { thread32_first(snapshot, &mut thread) }, 0);
    assert_eq!(last_error(), ERROR_NO_MORE_FILES);
}

/// An entry's dwSize stays as the caller set it: larger than the structure (300), or a
/// PROCESSENTRY32W's handed to the ANSI walk (556), which fills its PROCESSENTRY32 alone.
///
/// Pins: kernel32.Process32First, kernel32.Thread32First
#[test]
fn a_larger_dw_size_is_left_as_set() {
    install(machine());
    let snapshot = create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0);
    let mut wide = wide_entry();
    let ansi = (&mut wide as *mut ProcessEntry32W).cast::<ProcessEntry32>();
    wide.exe_file[200] = 0x7777;
    assert_eq!(unsafe { process32_first(snapshot, ansi) }, 1);
    assert_eq!(wide.size, 556);
    assert_eq!(
        wide.exe_file[200], 0x7777,
        "past the PROCESSENTRY32, untouched"
    );
    let mut entry = ProcessEntry32::zeroed();
    entry.size = 300;
    assert_eq!(unsafe { process32_first(snapshot, &mut entry) }, 1);
    assert_eq!((entry.size, entry.process_id), (300, 0));
    let mut thread = ThreadEntry32 {
        size: 32,
        ..Default::default()
    };
    assert_eq!(unsafe { thread32_first(snapshot, &mut thread) }, 1);
    assert_eq!(thread.size, 32);
}

/// An entry whose dwSize is short of its structure is ERROR_BAD_LENGTH, before the snapshot is
/// read; a handle that names no section is the map's error, ERROR_INVALID_HANDLE.
///
/// Pins: kernel32.Process32FirstW, kernel32.Process32First, kernel32.Thread32First
#[test]
fn a_short_entry_or_a_handle_of_no_snapshot_is_refused() {
    install(machine());
    let snapshot = create_toolhelp32_snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    let mut wide = wide_entry();
    wide.size = 296;
    assert_eq!(unsafe { process32_first_w(snapshot, &mut wide) }, 0);
    assert_eq!(last_error(), ERROR_BAD_LENGTH);
    let mut ansi = ProcessEntry32::zeroed();
    ansi.size = 295;
    assert_eq!(unsafe { process32_first(snapshot, &mut ansi) }, 0);
    assert_eq!(last_error(), ERROR_BAD_LENGTH);
    let mut thread = ThreadEntry32 {
        size: 27,
        ..Default::default()
    };
    assert_eq!(unsafe { thread32_first(snapshot, &mut thread) }, 0);
    assert_eq!(last_error(), ERROR_BAD_LENGTH);
    let mut wide = wide_entry();
    assert_eq!(unsafe { process32_first_w(0x7777, &mut wide) }, 0);
    assert_eq!(last_error(), ERROR_INVALID_HANDLE);
}

/// A listing longer than the first buffer is queried again at the length the service asks for:
/// every process is in the snapshot.
///
/// Pins: kernel32.CreateToolhelp32Snapshot
#[test]
fn a_long_listing_is_queried_again() {
    let mut processes = machine();
    for index in 0..120 {
        processes.push(ListedProcess {
            id: 100 + 4 * index,
            parent_id: 24,
            base_priority: 8,
            name: "averyveryverylo",
            threads: vec![ListedThread::new(1000 + 4 * index, 8)],
        });
    }
    install(processes);
    let snapshot = create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0);
    let (walked, _) = walk_w(snapshot);
    assert_eq!(walked.len(), 123);
    assert_eq!(walked[122].0, 100 + 4 * 119);
    assert_eq!(walked[122].4, "averyveryverylo");
}

/// A module list of the caller (process id 0) is a snapshot, holding no process or thread entry
/// when it names neither; one of a process id no process has is INVALID_HANDLE_VALUE with
/// ERROR_INVALID_PARAMETER, the process's open refused.
///
/// Pins: kernel32.CreateToolhelp32Snapshot
#[test]
fn a_module_list_names_its_process() {
    install(machine());
    let snapshot = create_toolhelp32_snapshot(TH32CS_SNAPMODULE, 0);
    assert_ne!(snapshot, INVALID_HANDLE_VALUE);
    let mut process = wide_entry();
    assert_eq!(unsafe { process32_first_w(snapshot, &mut process) }, 0);
    assert_eq!(last_error(), ERROR_NO_MORE_FILES);
    let refused = create_toolhelp32_snapshot(TH32CS_SNAPMODULE, 0x0F2F_2F2C);
    assert_eq!(refused, INVALID_HANDLE_VALUE);
    assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
    let with_processes = create_toolhelp32_snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS, 0);
    let (walked, _) = walk_w(with_processes);
    assert_eq!(walked.len(), 3);
}
