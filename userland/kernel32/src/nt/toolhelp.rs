//! The host tests' process listing and ToolHelp sections: once a test installs a listing
//! ([`install`]), NtQuerySystemInformation's stand-in answers SystemProcessInformation with it,
//! built as the kernel builds it, and paging-file sections get real memory, so a snapshot's views
//! hold what kernel32 writes into them.

use std::boxed::Box;
use std::cell::RefCell;
use std::vec::Vec;

use rtl::nt::info::{SystemProcessInformation, SystemThreadInformation};
use rtl::nt::{ClientId, UnicodeString};
use rtl::pod::Pod;
use rtl::status::{STATUS_INFO_LENGTH_MISMATCH, STATUS_OBJECT_TYPE_MISMATCH};
/// The first handle a backed section takes; each next one four on.
const FIRST_SECTION: u32 = 0x1000;

/// A listed thread: its client id and base priority (its current priority one above, waiting
/// for a user request).
#[derive(Clone, Debug)]
pub struct ListedThread {
    pub id: u32,
    pub base_priority: i32,
}

impl ListedThread {
    pub fn new(id: u32, base_priority: i32) -> Self {
        ListedThread { id, base_priority }
    }
}

/// A listed process: its client id, its creator's, its base priority, its image's name (empty:
/// none) and its threads.
#[derive(Clone, Debug)]
pub struct ListedProcess {
    pub id: u32,
    pub parent_id: u32,
    pub base_priority: i32,
    pub name: &'static str,
    pub threads: Vec<ListedThread>,
}

impl ListedProcess {
    /// The idle process: id 0, no name, its idle thread.
    pub fn idle() -> Self {
        ListedProcess {
            id: 0,
            parent_id: 0,
            base_priority: 0,
            name: "",
            threads: std::vec![ListedThread::new(0, 0)],
        }
    }
}

std::thread_local! {
    /// The processes the listing holds, once a test installs them.
    static PROCESSES: RefCell<Option<Vec<ListedProcess>>> = const { RefCell::new(None) };
    /// The backed sections, by handle: their memory.
    static SECTIONS: RefCell<Vec<(u32, Box<[u8]>)>> = const { RefCell::new(Vec::new()) };
}

/// The listing of `processes` for a buffer at `base`: each record, its threads, then its name
/// in its 32-byte room, terminated (the buffer's address in the caller's; MaximumLength the
/// room), the next record at the next 8-byte boundary.
pub fn listing(processes: &[ListedProcess], base: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut last: Option<usize> = None;
    for process in processes {
        let at = bytes.len().next_multiple_of(8);
        bytes.resize(at + size_of::<SystemProcessInformation>(), 0);
        for thread in &process.threads {
            let record = SystemThreadInformation {
                client_id: ClientId {
                    unique_process: process.id,
                    unique_thread: thread.id,
                },
                priority: thread.base_priority + 1,
                base_priority: thread.base_priority,
                thread_state: 5,
                wait_reason: 6,
                ..Pod::zeroed()
            };
            bytes.extend_from_slice(record.as_bytes());
        }
        let image_name = if process.name.is_empty() {
            UnicodeString::default()
        } else {
            let name_at = bytes.len();
            let units: Vec<u16> = process.name.encode_utf16().collect();
            let room = (2 * units.len() + 2).max(32);
            for unit in units.iter() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes.resize(name_at + room, 0);
            UnicodeString {
                length: 2 * units.len() as u16,
                maximum_length: room as u16,
                buffer: (base + name_at) as u32,
            }
        };
        let record = SystemProcessInformation {
            number_of_threads: process.threads.len() as u32,
            image_name,
            base_priority: process.base_priority,
            unique_process_id: process.id,
            inherited_from_unique_process_id: process.parent_id,
            ..Pod::zeroed()
        };
        bytes[at..at + size_of::<SystemProcessInformation>()].copy_from_slice(record.as_bytes());
        if let Some(last) = last {
            let next = ((at - last) as u32).to_le_bytes();
            bytes[last..last + 4].copy_from_slice(&next);
        }
        last = Some(at);
    }
    bytes
}

/// List `processes` from now on, and back the paging file's sections with memory.
pub fn install(processes: Vec<ListedProcess>) {
    PROCESSES.with(|listed| *listed.borrow_mut() = Some(processes));
}

/// NtQuerySystemInformation's process listing into the caller's buffer, when a test installed
/// one: the status (STATUS_INFO_LENGTH_MISMATCH for a buffer too short, a length of zero
/// reported, as Windows 2000's service reports).
///
/// # Safety
///
/// `information` holds `length` bytes; `return_length` is null or a dword.
pub unsafe fn query(information: *mut u8, length: u32, return_length: *mut u32) -> u32 {
    let listed = PROCESSES.with(|listed| listed.borrow().clone());
    let listed = listed.expect("a test installed a process listing");
    let bytes = listing(&listed, information as usize);
    let fits = bytes.len() <= length as usize;
    if !return_length.is_null() {
        // SAFETY: the caller's length (the contract).
        unsafe { return_length.write(if fits { bytes.len() as u32 } else { 0 }) };
    }
    if !fits {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    // SAFETY: the caller's buffer holds `length` bytes, at least the listing's (checked).
    unsafe { information.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len()) };
    0
}

/// Whether the test backs the paging file's sections (it installed a listing).
pub fn backing() -> bool {
    PROCESSES.with(|listed| listed.borrow().is_some())
}

/// A new backed section of `size` bytes (whole pages): its handle.
pub fn create_section(size: usize) -> u32 {
    SECTIONS.with(|sections| {
        let mut sections = sections.borrow_mut();
        let handle = FIRST_SECTION + 4 * sections.len() as u32;
        let memory = std::vec![0u8; size.next_multiple_of(0x1000)].into_boxed_slice();
        sections.push((handle, memory));
        handle
    })
}

/// A view of the backed section `section`: its memory's address and size, or the status of a
/// handle naming no section.
pub fn map(section: u32) -> Result<(usize, usize), u32> {
    SECTIONS.with(|sections| {
        let mut sections = sections.borrow_mut();
        let (_, memory) = sections
            .iter_mut()
            .find(|(handle, _)| *handle == section)
            .ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
        Ok((memory.as_mut_ptr() as usize, memory.len()))
    })
}
