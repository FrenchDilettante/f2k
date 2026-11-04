//! ToolHelp: a snapshot of the system's processes and threads (CreateToolhelp32Snapshot), walked
//! one entry at a time (Process32First/Next and their W forms, Thread32First/Next), as Windows
//! 2000's kernel32 keeps one. The snapshot is taken from NtQuerySystemInformation's process
//! listing (SystemProcessInformation), read into a buffer of kernel32's on the process heap, and
//! converted into a section of the paging file: a [`Header`] (each list's count, and each walk's
//! position), then the PROCESSENTRY32W array, then the THREADENTRY32 array. The section's handle
//! is the snapshot's: every walk call maps a view of it, reads its entry and moves its position,
//! and unmaps it, so the walk's state lives in the snapshot, shared by every holder of the handle,
//! and CloseHandle frees it.
//!
//! As the toolhelp fixture's capture shows Windows 2000's, a snapshot taking either the processes
//! or the threads takes both (each walk finds its entries whichever of the two flags named it), and
//! one taking neither holds no entry. A module or heap list names its process (zero: the caller):
//! one no process has is ERROR_INVALID_PARAMETER, the process's open refused; F2K records no
//! module or heap entries in the snapshot yet (Module32First and Heap32ListFirst are stubs).
//!
//! A walk call takes an entry whose `dwSize` holds its structure at least (ERROR_BAD_LENGTH
//! otherwise), fills the structure and leaves `dwSize` as the caller set it (the capture: 300
//! stays 300). The listing's buffer grows until the listing fits: Windows 2000's
//! NtQuerySystemInformation reports no length for a buffer too short.
//!
//! The entries hold what the listing tells: the client ids, the creator's id, the thread counts,
//! the process's base priority (`pcPriClassBase`) and each thread's (`tpBasePri`), and the image's
//! bare file name (`szExeFile`, `[System Process]` for the idle process, whose listed name is
//! none). The fields Windows 2000 keeps only for Windows 95's sake are zero: the usage counts, the
//! module and default-heap identifiers, the flags and the thread's priority delta.

use rtl::nt::info::{SystemProcessInformation, SystemThreadInformation};
use rtl::pod::Pod;

use crate::edge::Out;
use crate::error::{answer, bool_answer, Failure, ERROR_BAD_LENGTH, ERROR_NO_MORE_FILES};
use crate::heap::{HeapArray, Owned};
use crate::ntcall::{self, MappedView, NtStatus};

/// CreateToolhelp32Snapshot's flags: the lists a snapshot takes, and its handle's inheritance.
pub const TH32CS_SNAPHEAPLIST: u32 = 0x0000_0001;
pub const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
pub const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
pub const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
pub const TH32CS_INHERIT: u32 = 0x8000_0000;

/// SystemProcessInformation: NtQuerySystemInformation's process listing.
const SYSTEM_PROCESS_INFORMATION: u32 = 5;
/// The status of a listing buffer too short.
const STATUS_INFO_LENGTH_MISMATCH: NtStatus = 0xC000_0004;
const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;

/// A path's room in characters (MAX_PATH): `szExeFile`'s.
const MAX_PATH: usize = 260;

/// The name ToolHelp gives the idle process, whose listed name is none.
const IDLE_PROCESS_NAME: &str = "[System Process]";

/// The listing buffer's first size, and the step it grows by when the listing does not fit it.
const LISTING_START: usize = 0x4000;
const LISTING_STEP: usize = 0x4000;
/// The largest listing buffer a snapshot takes before it gives up: room for every process and
/// thread record a system holds many times over.
const LISTING_LIMIT: usize = 0x40_0000;

/// The section's access — STANDARD_RIGHTS_REQUIRED, SECTION_QUERY, SECTION_MAP_WRITE and
/// SECTION_MAP_READ, the capture's granted access — its pages' protection (PAGE_READWRITE) and its
/// allocation (SEC_COMMIT).
const SNAPSHOT_ACCESS: u32 = 0x000F_0007;
const PAGE_READWRITE: u32 = 0x04;
const SEC_COMMIT: u32 = 0x0800_0000;

/// The access a module or heap list opens its process with: PROCESS_QUERY_INFORMATION and
/// PROCESS_VM_READ.
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_VM_READ: u32 = 0x0010;

/// PROCESSENTRY32W (tlhelp32.h): one process of a snapshot.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessEntry32W {
    pub size: u32,
    pub usage: u32,
    pub process_id: u32,
    pub default_heap_id: u32,
    pub module_id: u32,
    pub threads: u32,
    pub parent_process_id: u32,
    pub pri_class_base: i32,
    pub flags: u32,
    pub exe_file: [u16; MAX_PATH],
}

/// PROCESSENTRY32: PROCESSENTRY32W's fields, the file name in the ANSI code page.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessEntry32 {
    pub size: u32,
    pub usage: u32,
    pub process_id: u32,
    pub default_heap_id: u32,
    pub module_id: u32,
    pub threads: u32,
    pub parent_process_id: u32,
    pub pri_class_base: i32,
    pub flags: u32,
    pub exe_file: [u8; MAX_PATH],
}

/// THREADENTRY32: one thread of a snapshot.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ThreadEntry32 {
    pub size: u32,
    pub usage: u32,
    pub thread_id: u32,
    pub owner_process_id: u32,
    pub base_pri: i32,
    pub delta_pri: i32,
    pub flags: u32,
}

/// The snapshot section's header: each list's count and the position of its walk (the index of
/// the entry the next Process32Next or Thread32Next answers). The process entries follow it, then
/// the thread entries.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Header {
    process_count: u32,
    process_position: u32,
    thread_count: u32,
    thread_position: u32,
}

// SAFETY: integers and arrays of them, without padding: each size asserted below is its fields'
// sum, so every byte belongs to a field and every bit pattern is a value.
unsafe impl Pod for ProcessEntry32W {}
// SAFETY: as above.
unsafe impl Pod for ProcessEntry32 {}
// SAFETY: as above.
unsafe impl Pod for ThreadEntry32 {}
// SAFETY: as above.
unsafe impl Pod for Header {}

const _: () = {
    assert!(size_of::<ProcessEntry32W>() == 556);
    assert!(size_of::<ProcessEntry32>() == 296);
    assert!(size_of::<ThreadEntry32>() == 28);
    assert!(size_of::<Header>() == 16);
};

/// The process listing as NtQuerySystemInformation wrote it into kernel32's buffer, which starts
/// at `base` (its names' buffers are addresses in it).
struct Listing<'a> {
    raw: &'a [u8],
    base: usize,
}

/// One process of the listing: its record, and where its threads' records start.
struct Listed {
    record: SystemProcessInformation,
    threads_at: usize,
}

impl Listing<'_> {
    /// The listing's processes, in its order: the chain of records from the first, each the
    /// previous one's `NextEntryOffset` on, to the one whose offset is zero. A record running
    /// past the buffer ends the walk.
    fn processes(&self) -> impl Iterator<Item = Listed> + '_ {
        let mut at = Some(0usize);
        core::iter::from_fn(move || {
            let offset = at?;
            let record = SystemProcessInformation::from_bytes(self.raw.get(offset..)?)?;
            at = match record.next_entry_offset {
                0 => None,
                next => offset.checked_add(next as usize),
            };
            Some(Listed {
                record,
                threads_at: offset + size_of::<SystemProcessInformation>(),
            })
        })
    }

    /// The threads of `process`: as many records as it counts, those inside the buffer.
    fn threads<'b>(
        &'b self,
        process: &Listed,
    ) -> impl Iterator<Item = SystemThreadInformation> + 'b {
        let at = process.threads_at;
        (0..process.record.number_of_threads as usize).map_while(move |index| {
            let offset = at + index * size_of::<SystemThreadInformation>();
            SystemThreadInformation::from_bytes(self.raw.get(offset..)?)
        })
    }

    /// The units of `process`'s image name, none when it has none (the idle process) or its
    /// buffer lies outside the listing's. The buffer is a 32-bit process's address: its offset in
    /// the listing is taken in 32 bits (the host tests' addresses are wider, cut alike).
    fn name(&self, process: &Listed) -> Option<&[u8]> {
        let name = process.record.image_name;
        if name.buffer == 0 {
            return None;
        }
        let offset = name.buffer.wrapping_sub(self.base as u32) as usize;
        self.raw
            .get(offset..offset.checked_add(usize::from(name.length))?)
            .filter(|bytes| !bytes.is_empty())
    }
}

/// `process`'s PROCESSENTRY32W: its ids, thread count, base priority and bare file name (the
/// listed name's part after its last backslash, cut to MAX_PATH with its terminator).
fn process_entry(listing: &Listing, process: &Listed) -> ProcessEntry32W {
    let mut exe_file = [0u16; MAX_PATH];
    let mut put = |units: &mut dyn Iterator<Item = u16>| {
        for (out, unit) in exe_file[..MAX_PATH - 1].iter_mut().zip(units) {
            *out = unit;
        }
    };
    match listing.name(process) {
        Some(bytes) => {
            let units = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&pair| u16::from_le_bytes(pair));
            let start = units
                .clone()
                .rposition(|unit| unit == u16::from(b'\\'))
                .map_or(0, |at| at + 1);
            put(&mut units.skip(start));
        }
        None => put(&mut IDLE_PROCESS_NAME.encode_utf16()),
    }
    let record = &process.record;
    ProcessEntry32W {
        size: size_of::<ProcessEntry32W>() as u32,
        usage: 0,
        process_id: record.unique_process_id,
        default_heap_id: 0,
        module_id: 0,
        threads: record.number_of_threads,
        parent_process_id: record.inherited_from_unique_process_id,
        pri_class_base: record.base_priority,
        flags: 0,
        exe_file,
    }
}

/// A listed thread's THREADENTRY32: its id, its process's, and its base priority.
fn thread_entry(thread: &SystemThreadInformation) -> ThreadEntry32 {
    ThreadEntry32 {
        size: size_of::<ThreadEntry32>() as u32,
        usage: 0,
        thread_id: thread.client_id.unique_thread,
        owner_process_id: thread.client_id.unique_process,
        base_pri: thread.base_priority,
        delta_pri: 0,
        flags: 0,
    }
}

/// The header of a snapshot of `listing`: its processes' and threads' counts, both walks at their
/// start.
fn header(listing: &Listing) -> Header {
    let mut header = Header::default();
    for process in listing.processes() {
        header.process_count += 1;
        header.thread_count += listing.threads(&process).count() as u32;
    }
    header
}

/// The bytes a snapshot with `header`'s counts takes.
fn snapshot_size(header: &Header) -> usize {
    size_of::<Header>()
        + header.process_count as usize * size_of::<ProcessEntry32W>()
        + header.thread_count as usize * size_of::<ThreadEntry32>()
}

/// Where a snapshot's thread entries start.
fn threads_offset(header: &Header) -> usize {
    size_of::<Header>() + header.process_count as usize * size_of::<ProcessEntry32W>()
}

/// Write `value`'s bytes at `offset` of `bytes`.
fn store<P: Pod>(bytes: &mut [u8], offset: usize, value: &P) {
    bytes[offset..offset + size_of::<P>()].copy_from_slice(value.as_bytes());
}

/// Fill `snapshot` (its [`snapshot_size`] at least) with `header` and the entries of `listing`, in
/// the listing's order.
fn fill(snapshot: &mut [u8], listing: &Listing, header: &Header) {
    store(snapshot, 0, header);
    let mut process_at = size_of::<Header>();
    let mut thread_at = threads_offset(header);
    for process in listing.processes() {
        store(snapshot, process_at, &process_entry(listing, &process));
        process_at += size_of::<ProcessEntry32W>();
        for thread in listing.threads(&process) {
            store(snapshot, thread_at, &thread_entry(&thread));
            thread_at += size_of::<ThreadEntry32>();
        }
    }
}

/// Which list a walk call reads.
#[derive(Clone, Copy)]
enum List {
    Processes,
    Threads,
}

/// The walk of `list` in `snapshot`: from its start for a First call, else from its position. The
/// entry's bytes at that position, the position moved past it; ERROR_NO_MORE_FILES past the end
/// (and for a snapshot that took no list: its counts are zero).
fn step(snapshot: &mut [u8], list: List, first: bool) -> Result<&[u8], Failure> {
    let mut header = Header::from_bytes(snapshot).ok_or(Failure::Error(ERROR_NO_MORE_FILES))?;
    let threads_start = threads_offset(&header);
    let (count, position, start, size) = match list {
        List::Processes => (
            header.process_count,
            &mut header.process_position,
            size_of::<Header>(),
            size_of::<ProcessEntry32W>(),
        ),
        List::Threads => (
            header.thread_count,
            &mut header.thread_position,
            threads_start,
            size_of::<ThreadEntry32>(),
        ),
    };
    if first {
        *position = 0;
    }
    let index = *position;
    if index < count {
        *position += 1;
    }
    store(snapshot, 0, &header);
    if index >= count {
        return Err(Failure::Error(ERROR_NO_MORE_FILES));
    }
    let at = start + index as usize * size;
    snapshot
        .get(at..at + size)
        .ok_or(Failure::Error(ERROR_NO_MORE_FILES))
}

/// The process listing, queried into a buffer of kernel32's that grows by [`LISTING_STEP`] until
/// the listing fits it (the service reports no length for a buffer too short), up to
/// [`LISTING_LIMIT`].
fn query_listing() -> Result<HeapArray<u8>, Failure> {
    let mut size = LISTING_START;
    loop {
        let mut raw = HeapArray::<u8>::new(size)?;
        match ntcall::query_system_information_into(SYSTEM_PROCESS_INFORMATION, &mut raw) {
            Ok(length) => {
                raw.truncate(length);
                return Ok(raw);
            }
            Err((STATUS_INFO_LENGTH_MISMATCH, _)) if size < LISTING_LIMIT => {
                size += LISTING_STEP;
            }
            Err((status, _)) => return Err(Failure::Status(status)),
        }
    }
}

/// The process a module or heap list names, `process_id` (zero: the caller), opened and closed
/// again: its open's error when no process has the id.
fn check_listed_process(process_id: u32) -> Result<(), Failure> {
    if process_id == 0 {
        return Ok(());
    }
    let attributes = ntcall::unnamed_attributes(false, core::ptr::null());
    let client_id = crate::nt::ClientId {
        unique_process: process_id as usize,
        unique_thread: 0,
    };
    let process = ntcall::open_process(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        &attributes,
        &client_id,
    )
    .map_err(Failure::Status)?;
    drop(Owned(process));
    Ok(())
}

/// A snapshot of the lists `flags` names: the listing, when it names the processes or the threads,
/// converted into a new section of the paging file, inheritable for TH32CS_INHERIT; its handle. A
/// module or heap list checks its process first (see [`check_listed_process`]).
fn create_snapshot(flags: u32, process_id: u32) -> Result<u32, Failure> {
    if flags & (TH32CS_SNAPMODULE | TH32CS_SNAPHEAPLIST) != 0 {
        check_listed_process(process_id)?;
    }
    let raw = if flags & (TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD) != 0 {
        Some(query_listing()?)
    } else {
        None
    };
    let listing = raw.as_ref().map(|raw| Listing {
        raw,
        base: raw.as_ptr() as usize,
    });
    let header = listing.as_ref().map(header).unwrap_or_default();
    let size = snapshot_size(&header) as i64;
    let attributes = ntcall::unnamed_attributes(flags & TH32CS_INHERIT != 0, core::ptr::null());
    let section = ntcall::create_section(
        SNAPSHOT_ACCESS,
        Some(&attributes),
        Some(&size),
        PAGE_READWRITE,
        SEC_COMMIT,
        0,
    )
    .map_err(Failure::Status)?;
    let section = Owned(section.handle);
    let mut view = MappedView::map(section.0).map_err(Failure::Status)?;
    match &listing {
        Some(listing) => fill(&mut view, listing, &header),
        None => store(&mut view, 0, &header),
    }
    Ok(section.into_raw())
}

/// CreateToolhelp32Snapshot: a snapshot of the system's processes and threads (TH32CS_SNAPPROCESS
/// or TH32CS_SNAPTHREAD: both lists, see the module doc), every process's and thread's whatever
/// `process_id` names (it names the process of a module or heap list), inheritable for
/// TH32CS_INHERIT; its handle, or INVALID_HANDLE_VALUE with the error.
#[unsafe(export_name = "f2k_export_CreateToolhelp32Snapshot")]
pub extern "system" fn create_toolhelp32_snapshot(flags: u32, process_id: u32) -> u32 {
    answer(create_snapshot(flags, process_id), INVALID_HANDLE_VALUE)
}

/// One walk call on the snapshot `snapshot`: its view mapped, `read` handed the entry the walk is
/// at, the view unmapped. A handle naming no section is the map's error.
fn walk<T>(
    snapshot: u32,
    list: List,
    first: bool,
    read: impl FnOnce(&[u8]) -> T,
) -> Result<T, Failure> {
    let mut view = MappedView::map(snapshot).map_err(Failure::Status)?;
    step(&mut view, list, first).map(read)
}

/// The `dwSize` of the caller's entry, when it holds a `T` at least; ERROR_BAD_LENGTH otherwise.
fn entry_size<T: Copy>(entry: &mut Out<'_, T>) -> Result<u32, Failure> {
    let size = entry.part::<u32>(0).get();
    if (size as usize) < size_of::<T>() {
        return Err(Failure::Error(ERROR_BAD_LENGTH));
    }
    Ok(size)
}

/// Process32FirstW and Process32NextW's work: the walk's next process into the caller's entry,
/// whose `dwSize` must hold a PROCESSENTRY32W, and stays as the caller set it.
fn process_w(snapshot: u32, mut entry: Out<'_, ProcessEntry32W>, first: bool) -> u32 {
    let walked = entry_size(&mut entry).and_then(|size| {
        walk(snapshot, List::Processes, first, |bytes| ProcessEntry32W {
            size,
            ..ProcessEntry32W::from_bytes(bytes).expect("a process entry's bytes")
        })
    });
    bool_answer(walked.map(|walked| entry.set(walked)))
}

/// Process32First and Process32Next's work: [`process_w`]'s, the file name converted to the ANSI
/// code page, into the caller's PROCESSENTRY32.
fn process_a(snapshot: u32, mut entry: Out<'_, ProcessEntry32>, first: bool) -> u32 {
    let walked = entry_size(&mut entry).and_then(|size| {
        walk(snapshot, List::Processes, first, |bytes| {
            ProcessEntry32W::from_bytes(bytes).expect("a process entry's bytes")
        })
        .map(|wide| ProcessEntry32 {
            size,
            ..narrowed(&wide)
        })
    });
    bool_answer(walked.map(|walked| entry.set(walked)))
}

/// A PROCESSENTRY32W as a PROCESSENTRY32: its file name through the ANSI code page.
fn narrowed(wide: &ProcessEntry32W) -> ProcessEntry32 {
    let mut exe_file = [0u8; MAX_PATH];
    let length = wide
        .exe_file
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(MAX_PATH - 1);
    ntcall::unicode_to_multi_byte_into(&mut exe_file[..MAX_PATH - 1], &wide.exe_file[..length]);
    ProcessEntry32 {
        size: size_of::<ProcessEntry32>() as u32,
        usage: wide.usage,
        process_id: wide.process_id,
        default_heap_id: wide.default_heap_id,
        module_id: wide.module_id,
        threads: wide.threads,
        parent_process_id: wide.parent_process_id,
        pri_class_base: wide.pri_class_base,
        flags: wide.flags,
        exe_file,
    }
}

/// Thread32First and Thread32Next's work: the walk's next thread into the caller's entry, whose
/// `dwSize` must hold a THREADENTRY32, and stays as the caller set it.
fn thread(snapshot: u32, mut entry: Out<'_, ThreadEntry32>, first: bool) -> u32 {
    let walked = entry_size(&mut entry).and_then(|size| {
        walk(snapshot, List::Threads, first, |bytes| ThreadEntry32 {
            size,
            ..ThreadEntry32::from_bytes(bytes).expect("a thread entry's bytes")
        })
    });
    bool_answer(walked.map(|walked| entry.set(walked)))
}

/// Process32FirstW: the snapshot's first process; ERROR_NO_MORE_FILES when it holds none.
///
/// # Safety
///
/// `entry` is a PROCESSENTRY32W whose `dwSize` the caller set.
#[unsafe(export_name = "f2k_export_Process32FirstW")]
pub unsafe extern "system" fn process32_first_w(snapshot: u32, entry: *mut ProcessEntry32W) -> u32 {
    // SAFETY: the caller's entry (the contract).
    process_w(snapshot, unsafe { Out::new(entry) }, true)
}

/// Process32NextW: the snapshot's next process; ERROR_NO_MORE_FILES past the last.
///
/// # Safety
///
/// As [`process32_first_w`].
#[unsafe(export_name = "f2k_export_Process32NextW")]
pub unsafe extern "system" fn process32_next_w(snapshot: u32, entry: *mut ProcessEntry32W) -> u32 {
    // SAFETY: the caller's entry (the contract).
    process_w(snapshot, unsafe { Out::new(entry) }, false)
}

/// Process32First: [`process32_first_w`], the file name in the ANSI code page.
///
/// # Safety
///
/// `entry` is a PROCESSENTRY32 whose `dwSize` the caller set.
#[unsafe(export_name = "f2k_export_Process32First")]
pub unsafe extern "system" fn process32_first(snapshot: u32, entry: *mut ProcessEntry32) -> u32 {
    // SAFETY: the caller's entry (the contract).
    process_a(snapshot, unsafe { Out::new(entry) }, true)
}

/// Process32Next: [`process32_next_w`], the file name in the ANSI code page.
///
/// # Safety
///
/// As [`process32_first`].
#[unsafe(export_name = "f2k_export_Process32Next")]
pub unsafe extern "system" fn process32_next(snapshot: u32, entry: *mut ProcessEntry32) -> u32 {
    // SAFETY: the caller's entry (the contract).
    process_a(snapshot, unsafe { Out::new(entry) }, false)
}

/// Thread32First: the snapshot's first thread; ERROR_NO_MORE_FILES when it holds none.
///
/// # Safety
///
/// `entry` is a THREADENTRY32 whose `dwSize` the caller set.
#[unsafe(export_name = "f2k_export_Thread32First")]
pub unsafe extern "system" fn thread32_first(snapshot: u32, entry: *mut ThreadEntry32) -> u32 {
    // SAFETY: the caller's entry (the contract).
    thread(snapshot, unsafe { Out::new(entry) }, true)
}

/// Thread32Next: the snapshot's next thread; ERROR_NO_MORE_FILES past the last.
///
/// # Safety
///
/// As [`thread32_first`].
#[unsafe(export_name = "f2k_export_Thread32Next")]
pub unsafe extern "system" fn thread32_next(snapshot: u32, entry: *mut ThreadEntry32) -> u32 {
    // SAFETY: the caller's entry (the contract).
    thread(snapshot, unsafe { Out::new(entry) }, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nt::toolhelp::{listing, ListedProcess, ListedThread};

    fn processes() -> std::vec::Vec<ListedProcess> {
        std::vec![
            ListedProcess::idle(),
            ListedProcess {
                id: 24,
                parent_id: 0,
                base_priority: 8,
                name: "sched.exe",
                threads: std::vec![ListedThread::new(28, 8), ListedThread::new(36, 10)],
            },
            ListedProcess {
                id: 32,
                parent_id: 24,
                base_priority: 13,
                name: "\\??\\C:\\WINNT\\system32\\ps.exe",
                threads: std::vec![ListedThread::new(40, 13)],
            },
        ]
    }

    /// A snapshot of the processes and threads over the stand-in listing, built in memory as the
    /// export builds it in its section.
    fn snapshot() -> std::vec::Vec<u8> {
        let raw = listing(&processes(), 0x0010_0000);
        let listing = Listing {
            raw: &raw,
            base: 0x0010_0000,
        };
        let header = header(&listing);
        let mut bytes = std::vec![0u8; snapshot_size(&header)];
        fill(&mut bytes, &listing, &header);
        bytes
    }

    fn name(entry: &ProcessEntry32W) -> std::string::String {
        let length = entry.exe_file.iter().position(|&unit| unit == 0).unwrap();
        std::string::String::from_utf16(&entry.exe_file[..length]).unwrap()
    }

    /// The process walk: every listed process in order, the idle one named `[System Process]`,
    /// a path cut to its file name; then ERROR_NO_MORE_FILES, until a First starts over.
    #[test]
    fn the_process_walk_lists_every_process_once() {
        let mut bytes = snapshot();
        let mut walked = std::vec::Vec::new();
        let mut first = true;
        while let Ok(entry) = step(&mut bytes, List::Processes, first) {
            walked.push(ProcessEntry32W::from_bytes(entry).unwrap());
            first = false;
        }
        let summary: std::vec::Vec<_> = walked
            .iter()
            .map(|entry| {
                (
                    entry.process_id,
                    entry.parent_process_id,
                    entry.threads,
                    entry.pri_class_base,
                    name(entry),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (0, 0, 1, 0, "[System Process]".into()),
                (24, 0, 2, 8, "sched.exe".into()),
                (32, 24, 1, 13, "ps.exe".into()),
            ]
        );
        assert!(walked.iter().all(|entry| entry.size == 556
            && entry.usage == 0
            && entry.module_id == 0
            && entry.default_heap_id == 0));
        assert_eq!(
            step(&mut bytes, List::Processes, false),
            Err(Failure::Error(ERROR_NO_MORE_FILES)),
            "past the end, and still past it"
        );
        let again = step(&mut bytes, List::Processes, true).map(<[u8]>::to_vec);
        assert_eq!(
            ProcessEntry32W::from_bytes(&again.unwrap())
                .unwrap()
                .process_id,
            0
        );
    }

    /// The thread walk: every thread of every process, each with its owner and base priority;
    /// its position is its own, apart from the process walk's.
    #[test]
    fn the_thread_walk_is_apart_from_the_process_walk() {
        let mut bytes = snapshot();
        step(&mut bytes, List::Processes, true).unwrap();
        let mut threads = std::vec::Vec::new();
        let mut first = true;
        while let Ok(entry) = step(&mut bytes, List::Threads, first) {
            let entry = ThreadEntry32::from_bytes(entry).unwrap();
            threads.push((entry.thread_id, entry.owner_process_id, entry.base_pri));
            assert_eq!((entry.size, entry.usage, entry.delta_pri), (28, 0, 0));
            first = false;
        }
        assert_eq!(
            threads,
            [(0, 0, 0), (28, 24, 8), (36, 24, 10), (40, 32, 13)]
        );
        let next = step(&mut bytes, List::Processes, false).map(<[u8]>::to_vec);
        assert_eq!(
            ProcessEntry32W::from_bytes(&next.unwrap())
                .unwrap()
                .process_id,
            24
        );
    }

    /// A snapshot of no list is its header alone, counts zero: both walks end at once.
    #[test]
    fn a_snapshot_of_no_list_has_no_entry() {
        let mut empty = [0u8; 16];
        store(&mut empty, 0, &Header::default());
        for list in [List::Processes, List::Threads] {
            assert_eq!(
                step(&mut empty, list, true),
                Err(Failure::Error(ERROR_NO_MORE_FILES))
            );
        }
    }

    /// A PROCESSENTRY32 is the wide entry with its name narrowed.
    #[test]
    fn the_ansi_entry_narrows_the_name() {
        let mut bytes = snapshot();
        step(&mut bytes, List::Processes, true).unwrap();
        let wide =
            ProcessEntry32W::from_bytes(step(&mut bytes, List::Processes, false).unwrap()).unwrap();
        let ansi = narrowed(&wide);
        assert_eq!(ansi.size, 296);
        assert_eq!((ansi.process_id, ansi.threads), (24, 2));
        assert_eq!(&ansi.exe_file[..10], b"sched.exe\0");
    }
}
