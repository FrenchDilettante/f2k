//! The programs' process list: kernel32's ToolHelp (CreateToolhelp32Snapshot, Process32FirstW,
//! Process32NextW), wrapped once, safely. A [`ProcessSnapshot`] is the system's processes at one
//! moment, closed when dropped; each [`ProcessSnapshot::processes`] walks it from its first entry,
//! yielding owned entries.

use crate::output::Error;
use crate::sys::MAX_PATH;

/// TH32CS_SNAPPROCESS: the snapshot holds the processes.
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
/// INVALID_HANDLE_VALUE: CreateToolhelp32Snapshot's failure.
const INVALID_HANDLE_VALUE: usize = usize::MAX;
/// ERROR_NO_MORE_FILES: a walk past its last entry.
const ERROR_NO_MORE_FILES: u32 = 18;

/// PROCESSENTRY32W (tlhelp32.h).
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessEntry32W {
    size: u32,
    usage: u32,
    process_id: u32,
    default_heap_id: usize,
    module_id: u32,
    threads: u32,
    parent_process_id: u32,
    pri_class_base: i32,
    flags: u32,
    exe_file: [u16; MAX_PATH],
}

const _: () = assert!(size_of::<ProcessEntry32W>() == 556);

#[link(
    name = "kernel32",
    kind = "raw-dylib",
    import_name_type = "undecorated"
)]
unsafe extern "system" {
    /// The calling thread's last error.
    fn GetLastError() -> u32;
    /// A snapshot of the lists `flags` names: its handle, INVALID_HANDLE_VALUE on failure.
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> usize;
    /// The snapshot's first process into the entry, whose dwSize the caller set: FALSE past the
    /// last.
    fn Process32FirstW(snapshot: usize, entry: *mut ProcessEntry32W) -> i32;
    /// The snapshot's next process: FALSE past the last.
    fn Process32NextW(snapshot: usize, entry: *mut ProcessEntry32W) -> i32;
    /// The handle closed.
    fn CloseHandle(handle: usize) -> i32;
}

/// The calling thread's last error, as an [`Error`].
fn last_error() -> Error {
    // SAFETY: no arguments; it reads the thread's own TEB.
    Error(unsafe { GetLastError() })
}

/// The system's processes at the moment it was taken (a ToolHelp snapshot), closed when dropped.
pub struct ProcessSnapshot(usize);

impl ProcessSnapshot {
    /// A snapshot of the processes running now.
    pub fn take() -> Result<ProcessSnapshot, Error> {
        // SAFETY: no pointers.
        match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
            INVALID_HANDLE_VALUE => Err(last_error()),
            handle => Ok(ProcessSnapshot(handle)),
        }
    }

    /// A walk of the snapshot's processes, from its first, in the snapshot's order.
    pub fn processes(&self) -> Processes<'_> {
        Processes {
            snapshot: self,
            first: true,
            done: false,
        }
    }
}

impl Drop for ProcessSnapshot {
    fn drop(&mut self) {
        // SAFETY: the snapshot's own handle, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// One process of a snapshot: its id, its creator's, its thread count, its base priority and its
/// image's file name.
#[derive(Clone, Copy)]
pub struct ProcessEntry {
    pub id: u32,
    pub parent_id: u32,
    pub threads: u32,
    pub base_priority: i32,
    name: [u16; MAX_PATH],
}

impl ProcessEntry {
    /// The image's file name, without its terminator.
    pub fn name(&self) -> &[u16] {
        let length = self
            .name
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(MAX_PATH);
        &self.name[..length]
    }
}

/// A walk of a snapshot's processes: each entry, or the error that ended the walk early.
pub struct Processes<'a> {
    snapshot: &'a ProcessSnapshot,
    first: bool,
    done: bool,
}

impl Iterator for Processes<'_> {
    type Item = Result<ProcessEntry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut entry = ProcessEntry32W {
            size: size_of::<ProcessEntry32W>() as u32,
            usage: 0,
            process_id: 0,
            default_heap_id: 0,
            module_id: 0,
            threads: 0,
            parent_process_id: 0,
            pri_class_base: 0,
            flags: 0,
            exe_file: [0; MAX_PATH],
        };
        let handle = self.snapshot.0;
        // SAFETY: the snapshot's handle, and the local entry with its dwSize set.
        let walked = unsafe {
            if self.first {
                Process32FirstW(handle, &mut entry)
            } else {
                Process32NextW(handle, &mut entry)
            }
        };
        self.first = false;
        if walked == 0 {
            self.done = true;
            let error = last_error();
            return (error.0 != ERROR_NO_MORE_FILES).then_some(Err(error));
        }
        Some(Ok(ProcessEntry {
            id: entry.process_id,
            parent_id: entry.parent_process_id,
            threads: entry.threads,
            base_priority: entry.pri_class_base,
            name: entry.exe_file,
        }))
    }
}
