//! The process listing: NtQuerySystemInformation's process information (SystemProcessInformation,
//! class 5), Windows 2000's chain of records. Each process is a SYSTEM_PROCESS_INFORMATION, its
//! threads' SYSTEM_THREAD_INFORMATION records right after it, then its image's name (the
//! UNICODE_STRING's buffer, in the caller's buffer, NUL-terminated); the next record starts at the
//! next 8-byte boundary, `NextEntryOffset` bytes on, and the last one's offset is zero.
//!
//! The listing is built in kernel memory first ([`Listing`]: the facts gathered at the levels that
//! guard them — a process's handle table and address space under their locks, its threads inside
//! a borrow of the dispatcher — never touching user memory there), then copied to the caller's
//! buffer at the passive level ([`query_processes`]). The idle process comes first, as on Windows
//! 2000, then the System process, then the processes in creation order (their client ids grow with
//! it). A process is listed until its last thread ends: one that has ended is not, whatever handles
//! hold it (the toolhelp fixture's capture).
//!
//! What F2K knows goes in: the client ids, the image names, the base and current priorities, the
//! thread states and wait reasons with the tick a wait began, the handle counts and the virtual
//! sizes. What it keeps no count of stays zero, the known gaps: the creation and CPU times (no
//! per-thread tick accounting yet), the context switches, the threads' start addresses, the page
//! faults, working set, pool and paging-file use, the private pages and the I/O counters.
//!
//! The idle process holds the idle thread, client id 0. The System process, client id 8 as on
//! Windows 2000, holds the kernel's system threads: F2K runs two, the console's control thread
//! (`crate::csr::ctrl`) and win32k's raw input thread (`crate::win32k::input`), where Windows
//! 2000's System process holds its executive's worker threads, its memory manager's and its cache
//! manager's too (a known gap).
//!
//! A buffer too short for the listing is STATUS_INFO_LENGTH_MISMATCH with a length of zero
//! reported, as the toolhelp fixture's capture shows Windows 2000's: the caller grows its buffer
//! and asks again, as kernel32's ToolHelp does.

use rtl::nt::info::{SystemProcessInformation, SystemThreadInformation};
use rtl::nt::{ClientId, UnicodeString};
use rtl::pod::Pod;

/// What the listing tells of a process.
#[derive(Clone, Copy)]
pub struct ProcessFacts<'a> {
    /// Its client id (zero: the idle process).
    pub id: u32,
    /// Its creator's client id (InheritedFromUniqueProcessId).
    pub parent_id: u32,
    /// Its base priority.
    pub base_priority: i8,
    /// How many handles its table holds.
    pub handle_count: u32,
    /// The bytes its address space reserves (VM_COUNTERS' VirtualSize; the peak is not kept).
    pub virtual_size: u32,
    /// Its image's file name; empty for the idle process, whose name is none.
    pub image_name: &'a str,
}

/// What the listing tells of a thread.
#[derive(Clone, Copy)]
pub struct ThreadFacts {
    /// Its client id (zero for the idle thread).
    pub id: u32,
    /// Its current priority.
    pub priority: i8,
    /// Its base priority.
    pub base_priority: i8,
    /// Its state (KTHREAD_STATE: `crate::sched::thread::ThreadState`'s values).
    pub state: u8,
    /// Why it waits, or last waited (KWAIT_REASON: `crate::sched::wait::WaitReason`'s values).
    pub wait_reason: u8,
    /// The tick its current or last wait began (KTHREAD's WaitTime, its low dword).
    pub wait_time: u32,
}

/// The records' alignment: each process record starts on it.
const RECORD_ALIGN: usize = 8;

/// The room an image name's buffer takes, in bytes: EPROCESS.ImageFileName's sixteen bytes (fifteen
/// and the terminator) as UTF-16 units. Every name takes it whole, as its MaximumLength: Windows
/// 2000's MaximumLength is not Length + 2 (the toolhelp fixture's capture), and the name's own
/// room is the one public documentation gives.
const NAME_BUFFER: usize = (crate::process::NAME_ROOM + 1) * 2;

/// The room a process record takes at most beside its threads': its structure and its name's
/// buffer, aligned.
const PROCESS_ROOM: usize = size_of::<SystemProcessInformation>() + NAME_BUFFER + RECORD_ALIGN;

/// The longest listing: every process record in use, the idle and System processes', every thread
/// record.
pub const LISTING_BOUND: usize = (crate::process::MAX_PROCESSES + 2) * PROCESS_ROOM
    + crate::sched::database::THREAD_RECORDS * size_of::<SystemThreadInformation>();

/// A listing built into `buffer` (kernel memory), for a caller whose buffer starts at `user_base`:
/// the image names' buffers are addresses there. What does not fit `buffer` is counted, not
/// written, so [`Listing::length`] is always the length the whole listing needs.
pub struct Listing<'b> {
    buffer: &'b mut [u8],
    user_base: u32,
    /// The bytes the listing takes so far.
    length: usize,
    /// The offset of the last process record closed, whose `NextEntryOffset` the next one sets.
    last: Option<usize>,
    /// The open process record: its offset and its threads so far.
    open: Option<(usize, u32)>,
}

impl<'b> Listing<'b> {
    /// An empty listing into `buffer`, for the caller's buffer at `user_base`.
    pub fn new(buffer: &'b mut [u8], user_base: u32) -> Self {
        Listing {
            buffer,
            user_base,
            length: 0,
            last: None,
            open: None,
        }
    }

    /// The length the listing needs: every record and name so far.
    pub fn length(&self) -> usize {
        self.length
    }

    /// The listing's bytes, when all of them fit.
    pub fn bytes(&self) -> Option<&[u8]> {
        self.buffer.get(..self.length)
    }

    /// Write `bytes` at `offset`, when they fit.
    fn put(&mut self, offset: usize, bytes: &[u8]) {
        if let Some(room) = self.buffer.get_mut(offset..offset + bytes.len()) {
            room.copy_from_slice(bytes);
        }
    }

    /// Open a process's record: its threads ([`Listing::thread`]) follow it, and
    /// [`Listing::close`] fills it.
    pub fn open(&mut self) {
        assert!(self.open.is_none(), "one process record open at a time");
        let offset = self.length.next_multiple_of(RECORD_ALIGN);
        self.open = Some((offset, 0));
        self.length = offset + size_of::<SystemProcessInformation>();
    }

    /// The open process's next thread, its process's client id being `process_id`.
    pub fn thread(&mut self, process_id: u32, thread: ThreadFacts) {
        let (offset, threads) = self
            .open
            .expect("a thread belongs to an open process record");
        let record = SystemThreadInformation {
            wait_time: thread.wait_time,
            client_id: ClientId {
                unique_process: process_id,
                unique_thread: thread.id,
            },
            priority: thread.priority.into(),
            base_priority: thread.base_priority.into(),
            thread_state: thread.state.into(),
            wait_reason: thread.wait_reason.into(),
            ..Pod::zeroed()
        };
        self.put(self.length, record.as_bytes());
        self.length += size_of::<SystemThreadInformation>();
        self.open = Some((offset, threads + 1));
    }

    /// Close the open process's record: its image's name after its threads (in a buffer of
    /// [`NAME_BUFFER`] bytes, terminated and zero-filled), then the record itself, linked from the
    /// one before it.
    pub fn close(&mut self, process: &ProcessFacts) {
        let (offset, threads) = self.open.take().expect("a process record is open");
        let image_name = if process.image_name.is_empty() {
            UnicodeString::default()
        } else {
            let at = self.length;
            let mut units = process
                .image_name
                .encode_utf16()
                .chain(core::iter::repeat(0));
            for index in 0..NAME_BUFFER / 2 {
                let unit = units.next().expect("the units go on as zeros");
                self.put(at + 2 * index, &unit.to_le_bytes());
            }
            self.length += NAME_BUFFER;
            let length = 2 * process.image_name.encode_utf16().count() as u16;
            UnicodeString {
                length,
                maximum_length: NAME_BUFFER as u16,
                buffer: self.user_base.wrapping_add(at as u32),
            }
        };
        let record = SystemProcessInformation {
            number_of_threads: threads,
            image_name,
            base_priority: process.base_priority.into(),
            unique_process_id: process.id,
            inherited_from_unique_process_id: process.parent_id,
            handle_count: process.handle_count,
            vm_counters: crate::nt::process::vm_counters(process.virtual_size),
            ..Pod::zeroed()
        };
        self.put(offset, record.as_bytes());
        if let Some(last) = self.last {
            let next = (offset - last) as u32;
            self.put(last, &next.to_le_bytes());
        }
        self.last = Some(offset);
    }
}

/// The idle process's facts: client id 0, no name (ToolHelp shows `[System Process]` for it), base
/// priority 0, no handles, no address space of its own.
pub const IDLE_PROCESS: ProcessFacts<'static> = ProcessFacts {
    id: 0,
    parent_id: 0,
    base_priority: 0,
    handle_count: 0,
    virtual_size: 0,
    image_name: "",
};

/// The System process's facts: client id 8 and no creator, as on Windows 2000, named `System`, its
/// base priority its record's. F2K's kernel keeps no handle table of its own and no address space
/// beside the boot directory: no handles, no virtual size.
pub const SYSTEM_PROCESS: ProcessFacts<'static> = ProcessFacts {
    id: crate::process::SYSTEM_PROCESS_ID,
    parent_id: 0,
    base_priority: 8,
    handle_count: 0,
    virtual_size: 0,
    image_name: "System",
};

#[cfg(target_arch = "x86")]
pub use target::query_processes;

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::level::{raised, Dispatch};
    use crate::nt::call::{NtResult, UserAddr, UserPtr};
    use crate::process::{Process, MAX_PROCESSES};
    use crate::sched::thread::Thread;
    use crate::sched::DISPATCHER;
    use crate::status::*;

    /// A thread record's facts.
    fn thread_facts(thread: &Thread) -> ThreadFacts {
        ThreadFacts {
            id: thread.thread_id(),
            priority: thread.priority(),
            base_priority: thread.base_priority(),
            state: thread.state() as u8,
            wait_reason: thread.wait_reason() as u8,
            wait_time: thread.wait_time() as u32,
        }
    }

    /// The record of one of the kernel's processes, `facts` its own, `record` its scheduling
    /// record: its threads (the idle thread; the system threads) and its base priority, in one
    /// borrow of the dispatcher.
    fn list_kernel_process(
        listing: &mut Listing,
        facts: &ProcessFacts,
        record: &'static crate::sched::process::PinnedProcess,
    ) {
        listing.open();
        let base_priority = raised::<Dispatch, _>(|dispatch| {
            let dispatcher = DISPATCHER.get(dispatch);
            for thread in crate::sched::census::threads_of(dispatcher, record.as_ptr()) {
                listing.thread(facts.id, thread_facts(thread));
            }
            record.get(dispatcher).base_priority()
        });
        listing.close(&ProcessFacts {
            base_priority,
            ..*facts
        });
    }

    /// `process`'s record: its handle count and virtual size under their locks, then its threads
    /// and base priority in one borrow of the dispatcher, so its thread count is its records'. A
    /// process that has ended reserves nothing any more (its address space goes with its reap).
    fn list_process(listing: &mut Listing, process: &Process) {
        let handle_count = process.with_handles(|table| table.live()) as u32;
        let virtual_size = if process.end().is_some() {
            0
        } else {
            process.with_space(|space| space.reserved_size())
        };
        let name = process.name();
        let id = process.id();
        listing.open();
        let base_priority = raised::<Dispatch, _>(|dispatch| {
            let dispatcher = DISPATCHER.get(dispatch);
            for thread in crate::sched::census::threads_of(dispatcher, process.sched_ptr()) {
                listing.thread(id, thread_facts(thread));
            }
            process.sched(dispatcher).base_priority()
        });
        listing.close(&ProcessFacts {
            id,
            parent_id: process.parent_id(),
            base_priority,
            handle_count,
            virtual_size,
            image_name: name.image_file_name(),
        });
    }

    /// NtQuerySystemInformation's process information into the caller's buffer of `length` bytes
    /// at `information`: the listing, and its length to `return_length`. A buffer too short for it
    /// is STATUS_INFO_LENGTH_MISMATCH with a length of zero reported (see the module doc); no pool
    /// memory for the listing is STATUS_INSUFFICIENT_RESOURCES.
    pub fn query_processes(
        information: UserAddr,
        length: u32,
        return_length: UserPtr<u32>,
    ) -> NtResult {
        information.probe(length)?;
        let mut block =
            crate::mem::pool::allocate(LISTING_BOUND).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let mut listing = Listing::new(block.as_mut(), information.raw());
        let (idle, system) = crate::sched::idle::kernel_processes();
        list_kernel_process(&mut listing, &IDLE_PROCESS, idle);
        list_kernel_process(&mut listing, &SYSTEM_PROCESS, system);
        let mut processes: [Option<&'static Process>; MAX_PROCESSES] = [None; MAX_PROCESSES];
        for (slot, process) in processes.iter_mut().zip(crate::process::pool::listed()) {
            *slot = Some(process);
        }
        processes.sort_unstable_by_key(|process| process.map_or(u32::MAX, Process::id));
        for process in processes.into_iter().flatten() {
            list_process(&mut listing, process);
        }
        let needed = listing.length() as u32;
        if needed > length {
            return_length.write_optional(0)?;
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        return_length.write_optional(needed)?;
        let bytes = listing
            .bytes()
            .expect("the listing fits its bound, every record counted in it");
        information.write(bytes)?;
        Ok(STATUS_SUCCESS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn thread(id: u32, state: u8) -> ThreadFacts {
        ThreadFacts {
            id,
            priority: 9,
            base_priority: 8,
            state,
            wait_reason: 6,
            wait_time: 0x1234,
        }
    }

    const BASE: u32 = 0x0012_0000;

    /// The listing of the idle process and one process of two threads.
    fn two_processes(buffer: &mut [u8]) -> usize {
        let mut listing = Listing::new(buffer, BASE);
        listing.open();
        listing.thread(0, thread(0, 2));
        listing.close(&IDLE_PROCESS);
        listing.open();
        listing.thread(24, thread(28, 5));
        listing.thread(24, thread(32, 1));
        listing.close(&ProcessFacts {
            id: 24,
            parent_id: 8,
            base_priority: 8,
            handle_count: 5,
            virtual_size: 0x0012_3000,
            image_name: "sched.exe",
        });
        listing.length()
    }

    /// The chain: the idle process with no name and its one thread, then the process with its
    /// two threads and its name after them, linked by the offset to the next 8-byte boundary.
    #[test]
    fn records_chain_with_their_threads_and_names() {
        let mut buffer = std::vec![0xAAu8; 4096];
        let length = two_processes(&mut buffer);
        let idle = &buffer[..];
        let next = word(idle, 0) as usize;
        assert_eq!(
            next,
            0xB8 + 0x40,
            "the idle process's record and its thread"
        );
        assert_eq!(word(idle, 4), 1);
        assert_eq!(&idle[0x38..0x40], &[0; 8], "no name, no buffer");
        assert_eq!((word(idle, 0x40), word(idle, 0x44)), (0, 0));
        assert_eq!(word(idle, 0xB8 + 0x34), 2, "the idle thread runs");

        let process = &buffer[next..];
        assert_eq!(word(process, 0), 0, "the last record");
        assert_eq!(word(process, 4), 2);
        assert_eq!(
            (
                word(process, 0x40),
                word(process, 0x44),
                word(process, 0x48)
            ),
            (8, 24, 8),
            "base priority, client id, creator"
        );
        assert_eq!(word(process, 0x4C), 5, "handles");
        assert_eq!(
            (word(process, 0x58), word(process, 0x5C)),
            (0x0012_3000, 0x0012_3000)
        );
        let second = &process[0xB8 + 0x40..];
        assert_eq!((word(second, 0x20), word(second, 0x24)), (24, 32));
        assert_eq!((word(second, 0x28), word(second, 0x2C)), (9, 8));
        assert_eq!((word(second, 0x34), word(second, 0x38)), (1, 6));
        assert_eq!(word(second, 0x18), 0x1234);

        let name_at = next + 0xB8 + 2 * 0x40;
        assert_eq!(
            (word(process, 0x38), word(process, 0x3C)),
            (18 | (32 << 16), BASE + name_at as u32),
            "Length, MaximumLength (the name's whole room, not Length + 2), and the buffer in the \
             caller's"
        );
        let units: std::vec::Vec<u16> = buffer[name_at..name_at + 32]
            .chunks(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert_eq!(
            String::from_utf16(&units).unwrap(),
            "sched.exe\0\0\0\0\0\0\0",
            "terminated, the rest of the room zero"
        );
        assert_eq!(length, name_at + 32);
    }

    /// A buffer too short still counts the whole listing: its length is what the caller needs.
    #[test]
    fn a_short_buffer_counts_the_whole_listing() {
        let mut whole = std::vec![0u8; 4096];
        let needed = two_processes(&mut whole);
        let mut short = std::vec![0u8; 0x40];
        assert_eq!(two_processes(&mut short), needed);
        let mut listing = Listing::new(&mut short, BASE);
        listing.open();
        listing.close(&IDLE_PROCESS);
        assert!(listing.bytes().is_none(), "the record does not fit");
    }

    /// The bound holds every process record with a name and every thread record.
    #[test]
    fn the_bound_holds_the_fullest_listing() {
        let mut buffer = std::vec![0u8; LISTING_BOUND];
        let mut listing = Listing::new(&mut buffer, BASE);
        let mut threads = crate::sched::database::THREAD_RECORDS as u32;
        for process in 0..crate::process::MAX_PROCESSES as u32 + 2 {
            listing.open();
            let share = if process == 0 { threads } else { 0 };
            for id in 0..share {
                listing.thread(process, thread(id, 5));
            }
            threads -= share;
            listing.close(&ProcessFacts {
                id: process,
                image_name: "averyveryverylo",
                ..IDLE_PROCESS
            });
        }
        assert!(listing.bytes().is_some());
    }
}
