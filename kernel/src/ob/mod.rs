//! The object manager: every kernel object a handle can name, with its lifetime.
//!
//! Objects live in typed pools of fixed capacity, global to the kernel rather than to a process
//! (one process runs at a time today; the pools are where a second one would find them). An object
//! is named by an [`ObjectId`] — its kind, its pool index and the generation of that record — never
//! by a raw pointer: the generation moves on when the object is deleted, so an id that outlived its
//! object resolves to nothing instead of to whatever reused the record.
//!
//! Each object carries two counts. The pointer count is every
//! reference: the creator's while it builds the object, each handle's, each wait's (a waiting
//! thread holds its objects for the wait's whole life, replays after an APC included), a thread's
//! own while it runs, a process's own until its teardown ends. The handle count is the handles
//! alone. The last handle's close drops the object's name (NT's temporary objects); the last
//! reference deletes the object — an owned mutex leaves its owner's list — and its record is free
//! for reuse. Nothing scans handle tables to decide whether an object lives. `\BaseNamedObjects`
//! itself is a directory object, permanent: made at its first open, never deleted.
//!
//! Names live in one namespace for all kinds (the `\BaseNamedObjects` directory): a name binds one
//! live object, compares exactly (Win32 object names are case-sensitive), and goes with the bound
//! object's last handle.
//!
//! A kind plugs in with its pool in [`Directory`], its arm in the kind matches (`header`, `id`,
//! `capacity`, `waitable`, the sweep), a `create_*` and a typed accessor, and — when its deletion
//! needs more than the record going dead (a timer leaving the timer table, an owned mutex its
//! owner's list) — an arm in `delete`; what the deletion leaves to the process (a section's frames,
//! a file object's cleanup and close) is a [`Followup`] variant the process finishes.
//!
//! The capacities are fixed (a create past them fails as the platform's out-of-memory would).

#[cfg(target_arch = "x86")]
use core::mem::MaybeUninit;

use crate::sched::dispatcher::Dispatcher;
use crate::sched::event::{Event, EventKind};
use crate::sched::mutex::Mutex;
use crate::sched::semaphore::Semaphore;
use crate::sched::thread::Thread;
use crate::sched::wait::{Waitable, MAXIMUM_WAIT_OBJECTS};
use crate::sched::waitable_timer::WaitableTimer;

/// The kinds of objects a handle can name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjectType {
    Event,
    Semaphore,
    Mutex,
    Timer,
    Thread,
    Process,
    Section,
    /// A file object: one open of a file or directory (see [`crate::fs::file`]).
    File,
    /// An object directory: `\BaseNamedObjects`, the one there is (permanent).
    Directory,
}

/// An object's identity: its kind, its record in that kind's pool, and the record's generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ObjectId {
    pub kind: ObjectType,
    pub index: u16,
    pub generation: u16,
}

/// What a handle-table entry names: an object (a directory search is kernel32's own structure on
/// the process heap, as on Windows 2000, not a kernel handle).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    Object(ObjectId),
}

/// One handle-table entry: what the handle names, the access it was granted, and whether a child
/// process would inherit it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub target: Target,
    pub access: u32,
    pub inherit: bool,
}

impl Entry {
    /// An entry naming an object.
    pub fn object(id: ObjectId, access: u32, inherit: bool) -> Self {
        Entry {
            target: Target::Object(id),
            access,
            inherit,
        }
    }

    /// The object the entry names, if it names one.
    pub fn object_id(&self) -> Option<ObjectId> {
        let Target::Object(id) = self.target;
        Some(id)
    }
}

/// The documented all-access masks, granted to the creator's handle (an event's the services
/// take from their caller: the tests' entries name it).
#[cfg_attr(not(test), allow(dead_code))]
pub const EVENT_ALL_ACCESS: u32 = 0x001F_0003;
pub const THREAD_ALL_ACCESS: u32 = 0x001F_03FF;
pub const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;
pub const SECTION_ALL_ACCESS: u32 = 0x000F_001F;

/// GetExitCodeProcess's and GetExitCodeThread's answer for one still running.
pub const STILL_ACTIVE: u32 = 259;

/// How many events can exist at once.
pub const EVENTS: usize = 256;
/// How many semaphores can exist at once.
pub const SEMAPHORES: usize = 64;
/// How many mutexes can exist at once.
pub const MUTEXES: usize = 64;
/// How many waitable timers can exist at once.
pub const TIMERS: usize = 32;
/// How many sections can exist at once.
pub const SECTIONS: usize = 16;
/// How many file objects can exist at once.
pub const FILES: usize = crate::fs::file::OPEN_FILES;
/// How many thread records exist: the current process's main thread (record 0) and its created
/// threads (records 1 on). A record's index is its thread's ordinal, which places its TEB and stack
/// pages (single-process for now: the ordinals are the process's).
pub const THREADS: usize = 1 + crate::process::CHILD_THREADS;
/// How many processes can exist at once: the process pool's records ([`crate::process::pool`]),
/// one process object each.
pub const PROCESSES: usize = crate::process::MAX_PROCESSES;
/// How many object directories exist: `\BaseNamedObjects`, the named objects' (permanent: made
/// at its first open, it is never deleted).
pub const DIRECTORIES: usize = 1;
/// How many names can be bound at once.
pub const NAMES: usize = 64;
/// The longest object name: MAX_PATH.
pub const MAX_NAME: usize = 260;

/// One record's header: whether it holds a live object, its generation, and the object's counts.
#[derive(Clone, Copy, Debug)]
pub struct Header {
    live: bool,
    generation: u16,
    pointers: u32,
    handles: u32,
}

impl Header {
    const fn dead() -> Self {
        Header {
            live: false,
            generation: 0,
            pointers: 0,
            handles: 0,
        }
    }
}

/// A fixed pool of records of one kind, each behind its header. Records stay at their addresses for
/// the kernel's life (waitable headers carry intrusive list links).
pub struct Pool<T, const N: usize> {
    headers: [Header; N],
    records: [T; N],
    /// How many records have ever been handed out (the high-water mark).
    used: usize,
}

impl<T, const N: usize> Pool<T, N> {
    /// Write an empty pool at `pool`, every record `fresh()`, element by element (by value it would
    /// pass through the caller's stack).
    ///
    /// # Safety
    ///
    /// `pool` is valid for writes and aligned; its previous contents are overwritten, not dropped.
    pub unsafe fn write_empty(pool: *mut Self, fresh: impl Fn() -> T) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written.
        unsafe {
            let headers = addr_of_mut!((*pool).headers) as *mut Header;
            let records = addr_of_mut!((*pool).records) as *mut T;
            for index in 0..N {
                headers.add(index).write(Header::dead());
                records.add(index).write(fresh());
            }
            addr_of_mut!((*pool).used).write(0);
        }
    }

    /// Take a free record in `range` for a new object: the lowest one holding no live object. The
    /// object starts with one reference (its creator's) and no handle. None when the range is
    /// exhausted. The record itself is the caller's to renew.
    fn allocate_in(&mut self, range: core::ops::Range<usize>) -> Option<u16> {
        let index = (range.start..range.end.min(N)).find(|&index| !self.headers[index].live)?;
        self.used = self.used.max(index + 1);
        let header = &mut self.headers[index];
        header.live = true;
        header.pointers = 1;
        header.handles = 0;
        Some(index as u16)
    }

    /// The record at `index`, live or not.
    pub fn record(&mut self, index: u16) -> &mut T {
        &mut self.records[index as usize]
    }

    /// The live record a generation names.
    fn get(&mut self, index: u16, generation: u16) -> Option<&mut T> {
        let header = self.headers.get(index as usize)?;
        (header.live && header.generation == generation).then(|| &mut self.records[index as usize])
    }

    /// The index of the record at `pointer`, if the pool holds it.
    fn index_of(&self, pointer: *const T) -> Option<u16> {
        let base = self.records.as_ptr() as usize;
        let at = pointer as usize;
        let size = core::mem::size_of::<T>();
        (at >= base && at < base + N * size && (at - base) % size == 0)
            .then(|| ((at - base) / size) as u16)
    }

    /// How many records hold a live object.
    fn live(&self) -> usize {
        self.headers.iter().filter(|header| header.live).count()
    }
}

/// A process object's body: what a wait on the process, or a handle to it, reaches. The process
/// record itself is the process pool's record at the same index; it is reused once the object is
/// deleted (the process holds its own reference from its creation to the end of its teardown).
pub struct ProcessObject {
    /// Signaled when the process has ended (no thread of the process outlives that, so its own
    /// threads only ever see it unsignaled).
    pub waitable: Waitable,
    /// The process's exit code: STILL_ACTIVE until it ends.
    pub exit_status: u32,
}

impl ProcessObject {
    const fn new() -> Self {
        ProcessObject {
            waitable: Waitable::new(crate::sched::wait::WaitKind::NotificationEvent, 0),
            exit_status: STILL_ACTIVE,
        }
    }
}

/// A section object's body: the mapping itself (on NT, the section and its segment). It is the
/// kernel's, not a process's: a view names it by its object, and its frames outlive the handle that
/// made it while a view references it.
#[derive(Clone, Copy)]
pub struct SectionObject {
    /// The mapped file, as its open found it (a file-backed section).
    pub file: crate::fs::fat32::lookup::File,
    /// Whether it is the paging file's (its pages start zeroed) rather than a file's.
    pub paging_file: bool,
    /// Its frames, page by page, made as views first need them.
    pub frames: crate::mem::vm::SectionFrames,
    /// The section's size in bytes.
    pub size: u32,
    /// Whether views may be writable (a read-write mapping).
    pub writable: bool,
    /// A file's section: the file object it holds (the file stays open while it is mapped).
    pub file_object: Option<ObjectId>,
    /// An image section's preferred base, where its one view maps (zero: a data section).
    pub image_base: u32,
}

impl SectionObject {
    /// A record holding no mapping (a pool's fresh record).
    pub const fn none() -> Self {
        SectionObject {
            file: crate::fs::fat32::lookup::File::plain(0, 0, false),
            paging_file: true,
            frames: crate::mem::vm::SectionFrames::empty(),
            size: 0,
            writable: false,
            file_object: None,
            image_base: 0,
        }
    }
}

/// What a caller must finish once an object's last handle or last reference went: the work outside
/// the object manager's reach, which the process finishes ([`crate::process::Process::finish`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Followup {
    /// A section was deleted: its frames (taken out of its record) and the file object a file's
    /// section held are the caller's to release.
    Section {
        frames: crate::mem::vm::SectionFrames,
        file_object: Option<ObjectId>,
    },
    /// A file object's last handle closed (its cleanup): its share access leaves the file's
    /// record, its delete-on-close marks the file delete-pending, and the last cleanup of a
    /// delete-pending file deletes it; its directory search (if any) goes back to the pool.
    FileCleanup {
        record: u16,
        access: u8,
        share: u8,
        delete_on_close: bool,
        search: u16,
    },
    /// A file object was deleted: its reference on the file's record goes.
    FileClose { record: u16 },
}

/// A program's object name as the namespace keeps it: without a `Global\` or `Local\` prefix.
/// There is one session, so the global namespace and the session's local one are the same
/// directory (Windows 2000 with Terminal Services keeps `\Sessions\<n>\BaseNamedObjects` apart).
/// The prefixes are matched as spelled.
pub fn namespace_name(name: &[u8]) -> &[u8] {
    name.strip_prefix(b"Global\\")
        .or_else(|| name.strip_prefix(b"Local\\"))
        .unwrap_or(name)
}

/// One name-table entry.
#[derive(Clone, Copy)]
struct NameEntry {
    object: Option<ObjectId>,
    length: u16,
    bytes: [u8; MAX_NAME],
}

impl NameEntry {
    const fn free() -> Self {
        NameEntry {
            object: None,
            length: 0,
            bytes: [0; MAX_NAME],
        }
    }

    fn name(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }
}

/// Why a name could not be bound.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NameError {
    /// The name is longer than an object name may be.
    TooLong,
    /// The name table is full.
    Full,
}

/// The references one thread's current wait holds: the objects it waits on.
#[derive(Clone, Copy)]
struct WaitReferences {
    objects: [Option<ObjectId>; MAXIMUM_WAIT_OBJECTS],
}

impl WaitReferences {
    const fn none() -> Self {
        WaitReferences {
            objects: [None; MAXIMUM_WAIT_OBJECTS],
        }
    }
}

/// Every object, by kind, with the namespace and the waits' references.
pub struct Directory {
    pub events: Pool<Event, EVENTS>,
    pub semaphores: Pool<Semaphore, SEMAPHORES>,
    pub mutexes: Pool<Mutex, MUTEXES>,
    pub timers: Pool<WaitableTimer, TIMERS>,
    pub threads: Pool<Thread, THREADS>,
    pub processes: Pool<ProcessObject, PROCESSES>,
    pub sections: Pool<SectionObject, SECTIONS>,
    pub files: Pool<crate::fs::file::FileObject, FILES>,
    pub directories: Pool<(), DIRECTORIES>,
    names: [NameEntry; NAMES],
    waits: [WaitReferences; THREADS],
}

impl Directory {
    /// Write an empty directory at `directory`: every pool empty, no names, no waits.
    ///
    /// # Safety
    ///
    /// `directory` is valid for writes, aligned, and the records' final address; its previous
    /// contents are overwritten, not dropped.
    pub unsafe fn write_empty(directory: *mut Directory) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written.
        unsafe {
            Pool::write_empty(addr_of_mut!((*directory).events), || {
                Event::new(EventKind::Notification, false)
            });
            Pool::write_empty(addr_of_mut!((*directory).semaphores), || Semaphore::new(0));
            Pool::write_empty(addr_of_mut!((*directory).mutexes), Mutex::new);
            Pool::write_empty(addr_of_mut!((*directory).timers), || {
                WaitableTimer::new(true)
            });
            Pool::write_empty(addr_of_mut!((*directory).threads), Thread::empty);
            Pool::write_empty(addr_of_mut!((*directory).processes), ProcessObject::new);
            Pool::write_empty(addr_of_mut!((*directory).sections), SectionObject::none);
            Pool::write_empty(addr_of_mut!((*directory).files), || {
                crate::fs::file::FileObject::new(0, 0, 0, 0)
            });
            Pool::write_empty(addr_of_mut!((*directory).directories), || ());
            let names = addr_of_mut!((*directory).names) as *mut NameEntry;
            for index in 0..NAMES {
                names.add(index).write(NameEntry::free());
            }
            let waits = addr_of_mut!((*directory).waits) as *mut WaitReferences;
            for index in 0..THREADS {
                waits.add(index).write(WaitReferences::none());
            }
        }
    }

    fn header(&mut self, id: ObjectId) -> Option<&mut Header> {
        let headers: &mut [Header] = match id.kind {
            ObjectType::Event => &mut self.events.headers,
            ObjectType::Semaphore => &mut self.semaphores.headers,
            ObjectType::Mutex => &mut self.mutexes.headers,
            ObjectType::Timer => &mut self.timers.headers,
            ObjectType::Thread => &mut self.threads.headers,
            ObjectType::Process => &mut self.processes.headers,
            ObjectType::Section => &mut self.sections.headers,
            ObjectType::File => &mut self.files.headers,
            ObjectType::Directory => &mut self.directories.headers,
        };
        let header = headers.get_mut(id.index as usize)?;
        (header.live && header.generation == id.generation).then_some(header)
    }

    fn id(&mut self, kind: ObjectType, index: u16) -> ObjectId {
        let generation = match kind {
            ObjectType::Event => self.events.headers[index as usize].generation,
            ObjectType::Semaphore => self.semaphores.headers[index as usize].generation,
            ObjectType::Mutex => self.mutexes.headers[index as usize].generation,
            ObjectType::Timer => self.timers.headers[index as usize].generation,
            ObjectType::Thread => self.threads.headers[index as usize].generation,
            ObjectType::Process => self.processes.headers[index as usize].generation,
            ObjectType::Section => self.sections.headers[index as usize].generation,
            ObjectType::File => self.files.headers[index as usize].generation,
            ObjectType::Directory => self.directories.headers[index as usize].generation,
        };
        ObjectId {
            kind,
            index,
            generation,
        }
    }

    /// Whether `id` names a live object.
    pub fn is_live(&mut self, id: ObjectId) -> bool {
        self.header(id).is_some()
    }

    /// An object's (pointer, handle) counts; none for an id that names nothing.
    #[cfg(test)]
    pub fn counts(&mut self, id: ObjectId) -> Option<(u32, u32)> {
        self.header(id)
            .map(|header| (header.pointers, header.handles))
    }

    // --- Creation ----------------------------------------------------------------------------

    /// A fresh event of `kind` at `signaled`, holding its creator's reference; none when the pool
    /// is exhausted.
    pub fn create_event(&mut self, kind: EventKind, signaled: bool) -> Option<ObjectId> {
        let index = self.events.allocate_in(0..EVENTS)?;
        let event = self.events.record(index);
        *event = Event::new(kind, signaled);
        event.init();
        Some(self.id(ObjectType::Event, index))
    }

    /// A fresh semaphore at `initial` with ceiling `limit`.
    pub fn create_semaphore(&mut self, initial: i32, limit: i32) -> Option<ObjectId> {
        let index = self.semaphores.allocate_in(0..SEMAPHORES)?;
        let semaphore = self.semaphores.record(index);
        *semaphore = Semaphore::new(limit);
        semaphore.init();
        semaphore.waitable.signal_state = initial;
        Some(self.id(ObjectType::Semaphore, index))
    }

    /// A fresh, free mutex.
    pub fn create_mutex(&mut self) -> Option<ObjectId> {
        let index = self.mutexes.allocate_in(0..MUTEXES)?;
        let mutex = self.mutexes.record(index);
        *mutex = Mutex::new();
        mutex.init();
        Some(self.id(ObjectType::Mutex, index))
    }

    /// A fresh, unarmed, unsignaled waitable timer.
    pub fn create_timer(&mut self, manual_reset: bool) -> Option<ObjectId> {
        let index = self.timers.allocate_in(0..TIMERS)?;
        let timer = self.timers.record(index);
        *timer = WaitableTimer::new(manual_reset);
        timer.init();
        Some(self.id(ObjectType::Timer, index))
    }

    /// A thread record for a new thread object, in `range` (record 0 is the main thread's; created
    /// threads take 1 on). The record is returned as it was left — a dead thread's record still
    /// holds what its pages need for release; the caller renews it. Holds the thread's own
    /// reference, released when the thread ends.
    pub fn create_thread_in(&mut self, range: core::ops::Range<usize>) -> Option<ObjectId> {
        let index = self.threads.allocate_in(range)?;
        Some(self.id(ObjectType::Thread, index))
    }

    /// A process object for a new process, unsignaled and still active, holding the process's own
    /// reference; none when every process record is in use. Its index is the process record's.
    pub fn create_process(&mut self) -> Option<ObjectId> {
        let index = self.processes.allocate_in(0..PROCESSES)?;
        let process = self.processes.record(index);
        *process = ProcessObject::new();
        process.waitable.init();
        Some(self.id(ObjectType::Process, index))
    }

    /// A section object holding `section` (the mapping).
    pub fn create_section(&mut self, section: SectionObject) -> Option<ObjectId> {
        let index = self.sections.allocate_in(0..SECTIONS)?;
        *self.sections.record(index) = section;
        Some(self.id(ObjectType::Section, index))
    }

    /// A file object of file record `record`, opened for `access` (as the share check reads it;
    /// `granted` the file rights) and allowing `share`.
    pub fn create_file(
        &mut self,
        record: u16,
        access: u8,
        granted: u32,
        share: u8,
    ) -> Option<ObjectId> {
        let index = self.files.allocate_in(0..FILES)?;
        let file = self.files.record(index);
        *file = crate::fs::file::FileObject::new(record, access, granted, share);
        file.init();
        Some(self.id(ObjectType::File, index))
    }

    // --- Typed access ------------------------------------------------------------------------

    pub fn event(&mut self, id: ObjectId) -> Option<&mut Event> {
        (id.kind == ObjectType::Event).then_some(())?;
        self.events.get(id.index, id.generation)
    }

    pub fn semaphore(&mut self, id: ObjectId) -> Option<&mut Semaphore> {
        (id.kind == ObjectType::Semaphore).then_some(())?;
        self.semaphores.get(id.index, id.generation)
    }

    pub fn mutex(&mut self, id: ObjectId) -> Option<&mut Mutex> {
        (id.kind == ObjectType::Mutex).then_some(())?;
        self.mutexes.get(id.index, id.generation)
    }

    pub fn timer(&mut self, id: ObjectId) -> Option<&mut WaitableTimer> {
        (id.kind == ObjectType::Timer).then_some(())?;
        self.timers.get(id.index, id.generation)
    }

    pub fn thread(&mut self, id: ObjectId) -> Option<&mut Thread> {
        (id.kind == ObjectType::Thread).then_some(())?;
        self.threads.get(id.index, id.generation)
    }

    pub fn process(&mut self, id: ObjectId) -> Option<&mut ProcessObject> {
        (id.kind == ObjectType::Process).then_some(())?;
        self.processes.get(id.index, id.generation)
    }

    pub fn section(&mut self, id: ObjectId) -> Option<&mut SectionObject> {
        (id.kind == ObjectType::Section).then_some(())?;
        self.sections.get(id.index, id.generation)
    }

    pub fn file(&mut self, id: ObjectId) -> Option<&mut crate::fs::file::FileObject> {
        (id.kind == ObjectType::File).then_some(())?;
        self.files.get(id.index, id.generation)
    }

    /// The live process object at process pool `index`, if any.
    pub fn processes_live(&mut self, index: u16) -> Option<ObjectId> {
        let id = self.id(ObjectType::Process, index);
        self.is_live(id).then_some(id)
    }

    /// The process `id` names has ended with `exit_status`: its object signals, once, and its
    /// waiters wake (no boost: the end grants none).
    pub fn signal_process_end(
        &mut self,
        id: ObjectId,
        exit_status: u32,
        dispatcher: &mut Dispatcher,
    ) {
        let Some(process) = self.process(id) else {
            return;
        };
        process.exit_status = exit_status;
        process.waitable.signal_state = 1;
        let waitable = core::ptr::addr_of_mut!(process.waitable);
        // SAFETY: the waitable is the live process object's, initialized at its creation.
        if !unsafe { (*waitable).waiters.is_empty() } {
            dispatcher.satisfy_waiters(waitable, 0);
        }
    }

    /// The waitable header of a waitable object; none for a section, a file object (its I/O
    /// completes at once: nothing waits on it), the directory or a dead id.
    pub fn waitable(&mut self, id: ObjectId) -> Option<*mut Waitable> {
        match id.kind {
            ObjectType::Event => self.event(id).map(Event::waitable),
            ObjectType::Semaphore => self.semaphore(id).map(Semaphore::waitable),
            ObjectType::Mutex => self.mutex(id).map(Mutex::waitable),
            ObjectType::Timer => self.timer(id).map(WaitableTimer::waitable),
            ObjectType::Thread => self.thread(id).map(Thread::waitable),
            ObjectType::Process => self
                .process(id)
                .map(|process| core::ptr::addr_of_mut!(process.waitable)),
            ObjectType::Section | ObjectType::File | ObjectType::Directory => None,
        }
    }

    /// The thread object whose record is at `thread`; none for a record outside the pool (the idle
    /// thread's) or one holding no live object.
    pub fn thread_id_of(&mut self, thread: *const Thread) -> Option<ObjectId> {
        let index = self.threads.index_of(thread)?;
        let id = self.id(ObjectType::Thread, index);
        self.is_live(id).then_some(id)
    }

    // --- Counts --------------------------------------------------------------------------------

    /// Take a reference on `id`; false when it names nothing.
    pub fn reference(&mut self, id: ObjectId) -> bool {
        match self.header(id) {
            Some(header) => {
                header.pointers += 1;
                true
            }
            None => false,
        }
    }

    /// Drop a reference on `id`; the last one deletes the object. Returns what the caller must
    /// finish for a deleted object.
    pub fn dereference(&mut self, id: ObjectId, dispatcher: &mut Dispatcher) -> Option<Followup> {
        let header = self.header(id)?;
        debug_assert!(
            header.pointers > header.handles,
            "a reference beyond the handles' is held"
        );
        header.pointers -= 1;
        if header.pointers == 0 {
            return self.delete(id, dispatcher);
        }
        None
    }

    /// A handle to `id` was inserted: one handle more, and its reference.
    pub fn handle_opened(&mut self, id: ObjectId) -> bool {
        match self.header(id) {
            Some(header) => {
                header.handles += 1;
                header.pointers += 1;
                true
            }
            None => false,
        }
    }

    /// A handle to `id` was closed: the last handle drops the object's name and cleans up a file
    /// object, and the handle's reference goes with it (the last reference deletes the object).
    /// What the caller must finish is handed to `finish`, in order.
    pub fn handle_closed(
        &mut self,
        id: ObjectId,
        dispatcher: &mut Dispatcher,
        mut finish: impl FnMut(Followup),
    ) {
        let Some(header) = self.header(id) else {
            return;
        };
        debug_assert!(header.handles > 0, "a handle closes once");
        header.handles -= 1;
        if header.handles == 0 {
            self.forget_name(id);
            if id.kind == ObjectType::File {
                let file = self.files.record(id.index);
                finish(Followup::FileCleanup {
                    record: file.record,
                    access: file.access,
                    share: file.share,
                    delete_on_close: file.delete_on_close,
                    search: file.search,
                });
            }
        }
        if let Some(followup) = self.dereference(id, dispatcher) {
            finish(followup);
        }
    }

    /// Delete the object `id` names: its kind's teardown, then the record is dead and its id stale.
    /// A section leaves its frames (and a file's section its file object) to the caller, a file
    /// object its record's reference; an owned mutex leaves its owner's list; no other
    /// kind here needs more than the record going: a waitable's last reference is gone, so nothing
    /// waits on it; a thread's record stays as it ended (its pages are released when the record is
    /// reused); a process's record is free for the next process once its object is gone.
    fn delete(&mut self, id: ObjectId, dispatcher: &mut Dispatcher) -> Option<Followup> {
        let followup = match id.kind {
            ObjectType::Timer => {
                // Nothing may expire or queue an APC for a timer no one can reach.
                let timer = self.timers.record(id.index);
                dispatcher.cancel_waitable_timer(timer);
                None
            }
            ObjectType::Mutex => {
                // An owned mutex leaves its owner's list (the owner's end has nothing to abandon).
                dispatcher.forget_mutex(self.mutexes.record(id.index));
                None
            }
            ObjectType::Section => {
                let section =
                    core::mem::replace(self.sections.record(id.index), SectionObject::none());
                Some(Followup::Section {
                    frames: section.frames,
                    file_object: section.file_object,
                })
            }
            ObjectType::File => Some(Followup::FileClose {
                record: self.files.record(id.index).record,
            }),
            ObjectType::Event
            | ObjectType::Semaphore
            | ObjectType::Thread
            | ObjectType::Process
            | ObjectType::Directory => None,
        };
        self.forget_name(id);
        let header = self.header(id).expect("deleting a live object");
        header.live = false;
        header.pointers = 0;
        header.handles = 0;
        header.generation = header.generation.wrapping_add(1);
        followup
    }

    // --- Names -------------------------------------------------------------------------------

    /// The live object `name` binds (its session prefix aside, see [`namespace_name`]).
    pub fn lookup_name(&self, name: &[u8]) -> Option<ObjectId> {
        let name = namespace_name(name);
        self.names
            .iter()
            .find_map(|entry| entry.object.filter(|_| entry.name() == name))
    }

    /// Bind `name` to `id` (its session prefix aside).
    pub fn bind_name(&mut self, name: &[u8], id: ObjectId) -> Result<(), NameError> {
        let name = namespace_name(name);
        if name.len() > MAX_NAME {
            return Err(NameError::TooLong);
        }
        let entry = self
            .names
            .iter_mut()
            .find(|entry| entry.object.is_none())
            .ok_or(NameError::Full)?;
        entry.object = Some(id);
        entry.length = name.len() as u16;
        entry.bytes[..name.len()].copy_from_slice(name);
        Ok(())
    }

    /// Forget the name bound to `id`, if any.
    fn forget_name(&mut self, id: ObjectId) {
        for entry in self.names.iter_mut() {
            if entry.object == Some(id) {
                *entry = NameEntry::free();
            }
        }
    }

    // --- Waits -------------------------------------------------------------------------------

    /// The wait thread record `thread` is about to enter holds `objects` for its whole life: a
    /// reference on each, released by [`Directory::release_wait`] when the wait returns — or when
    /// the thread ends without returning.
    pub fn hold_wait(&mut self, thread: u16, objects: &[ObjectId]) {
        debug_assert!(self.waits[thread as usize]
            .objects
            .iter()
            .all(Option::is_none));
        for (slot, &id) in self.waits[thread as usize].objects.iter_mut().zip(objects) {
            *slot = Some(id);
        }
        for &id in objects {
            let held = self.reference(id);
            debug_assert!(held, "a wait holds live objects");
        }
    }

    /// Release the references thread record `thread`'s wait holds; the followups of objects that
    /// went with them are handed to `finish`.
    pub fn release_wait(
        &mut self,
        thread: u16,
        dispatcher: &mut Dispatcher,
        mut finish: impl FnMut(Followup),
    ) {
        let held = core::mem::replace(&mut self.waits[thread as usize], WaitReferences::none());
        for id in held.objects.iter().flatten() {
            if let Some(followup) = self.dereference(*id, dispatcher) {
                finish(followup);
            }
        }
    }

    // --- Rundown -----------------------------------------------------------------------------

    /// Cancel every live timer whose completion APC targets `thread` (it is ending: nothing may
    /// queue to it any more).
    pub fn run_down_timers(&mut self, dispatcher: &mut Dispatcher, thread: *mut Thread) {
        for index in 0..self.timers.used {
            if self.timers.headers[index].live
                && core::ptr::eq(self.timers.records[index].apc_thread(), thread)
            {
                dispatcher.cancel_waitable_timer(&mut self.timers.records[index]);
            }
        }
    }

    /// The process is gone (one process at a time: every object was its own): every object still
    /// live is deleted — none should be, once its handles closed and its threads ended — and every
    /// thread record starts over (its pages went with the address space). Returns how many objects
    /// outlived their process; what a deleted one leaves (a leaked section's hold on its frames) is
    /// handed to `finish`. Process objects are not swept: a process's own goes with its own
    /// reference, at its teardown's end.
    pub fn process_ended(
        &mut self,
        dispatcher: &mut Dispatcher,
        mut finish: impl FnMut(Followup),
    ) -> usize {
        // The processes outlive their own end, and the permanent directory every process.
        let leaked = self.live_objects() - self.processes.live() - self.directories.live();
        for kind in [
            ObjectType::Event,
            ObjectType::Semaphore,
            ObjectType::Mutex,
            ObjectType::Timer,
            ObjectType::Thread,
            ObjectType::Section,
            ObjectType::File,
        ] {
            for index in 0..self.capacity(kind) {
                let id = self.id(kind, index as u16);
                if self.is_live(id) {
                    if let Some(followup) = self.delete(id, dispatcher) {
                        finish(followup);
                    }
                }
            }
        }
        for index in 0..THREADS {
            *self.threads.record(index as u16) = Thread::empty();
            self.waits[index] = WaitReferences::none();
        }
        for entry in self.names.iter_mut() {
            *entry = NameEntry::free();
        }
        leaked
    }

    fn capacity(&self, kind: ObjectType) -> usize {
        match kind {
            ObjectType::Event => EVENTS,
            ObjectType::Semaphore => SEMAPHORES,
            ObjectType::Mutex => MUTEXES,
            ObjectType::Timer => TIMERS,
            ObjectType::Thread => THREADS,
            ObjectType::Process => PROCESSES,
            ObjectType::Section => SECTIONS,
            ObjectType::File => FILES,
            ObjectType::Directory => DIRECTORIES,
        }
    }

    /// How many objects are live, of every kind.
    pub fn live_objects(&self) -> usize {
        self.events.live()
            + self.semaphores.live()
            + self.mutexes.live()
            + self.timers.live()
            + self.threads.live()
            + self.processes.live()
            + self.sections.live()
            + self.files.live()
            + self.directories.live()
    }

    /// `\BaseNamedObjects`, the named objects' directory: made at its first open and permanent
    /// (its creator's reference is never dropped, so no process's end deletes it).
    pub fn named_objects(&mut self) -> Option<ObjectId> {
        if !self.directories.headers[0].live {
            self.directories.allocate_in(0..DIRECTORIES)?;
        }
        Some(self.id(ObjectType::Directory, 0))
    }
}

// --- The kernel's directory -------------------------------------------------------------------

/// The kernel's one directory, built in place at first use (by value it would pass the stack).
#[cfg(target_arch = "x86")]
static mut DIRECTORY: MaybeUninit<Directory> = MaybeUninit::uninit();

/// Whether [`DIRECTORY`] is built.
#[cfg(target_arch = "x86")]
static mut BUILT: bool = false;

/// The kernel's directory of objects.
#[cfg(target_arch = "x86")]
pub fn directory() -> &'static mut Directory {
    // SAFETY: single CPU; services and the teardown run serialized (the gate masks interrupts), and
    // no interrupt path reaches the directory. Built once, in place, before the first use.
    unsafe {
        let directory = (*core::ptr::addr_of_mut!(DIRECTORY)).as_mut_ptr();
        if !BUILT {
            Directory::write_empty(directory);
            BUILT = true;
        }
        &mut *directory
    }
}

// --- The services' side (the current process's handles) ----------------------------------------

/// A reference on an object, held for as long as the value lives:
/// dropping it releases the reference, and the last one deletes the object.
#[cfg(target_arch = "x86")]
pub struct ObRef {
    id: ObjectId,
}

#[cfg(target_arch = "x86")]
impl ObRef {
    /// The referenced object's id.
    pub fn id(&self) -> ObjectId {
        self.id
    }

    /// The referenced event (the reference's kind is the caller's to know).
    pub fn event(&self) -> &'static mut Event {
        directory()
            .event(self.id)
            .expect("a referenced event lives")
    }

    pub fn semaphore(&self) -> &'static mut Semaphore {
        directory()
            .semaphore(self.id)
            .expect("a referenced semaphore lives")
    }

    pub fn mutex(&self) -> &'static mut Mutex {
        directory()
            .mutex(self.id)
            .expect("a referenced mutex lives")
    }

    pub fn timer(&self) -> &'static mut WaitableTimer {
        directory()
            .timer(self.id)
            .expect("a referenced timer lives")
    }

    pub fn thread(&self) -> &'static mut Thread {
        directory()
            .thread(self.id)
            .expect("a referenced thread lives")
    }

    pub fn section(&self) -> &'static mut SectionObject {
        directory()
            .section(self.id)
            .expect("a referenced section lives")
    }
}

#[cfg(target_arch = "x86")]
impl Drop for ObRef {
    fn drop(&mut self) {
        release(self.id);
    }
}

/// A referenced object's record: the reference lives as long as the value, which reads as the
/// record itself.
#[cfg(target_arch = "x86")]
pub struct Referenced<T: 'static> {
    _reference: ObRef,
    record: *mut T,
}

#[cfg(target_arch = "x86")]
impl<T: 'static> Referenced<T> {
    /// `record`, held through `reference` (the record is the referenced object's own).
    pub fn new(reference: ObRef, record: &'static mut T) -> Self {
        Referenced {
            _reference: reference,
            record,
        }
    }

    /// The referenced object's id.
    pub fn id(&self) -> ObjectId {
        self._reference.id()
    }
}

#[cfg(target_arch = "x86")]
impl<T: 'static> core::ops::Deref for Referenced<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the record is a pool record, static, and its object is held for the value's life.
        unsafe { &*self.record }
    }
}

#[cfg(target_arch = "x86")]
impl<T: 'static> core::ops::DerefMut for Referenced<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as `deref`; services run serialized, so the record has no other user meanwhile.
        unsafe { &mut *self.record }
    }
}

/// Take a reference on `id` for the caller's scope; none when it names nothing.
#[cfg(target_arch = "x86")]
pub fn reference(id: ObjectId) -> Option<ObRef> {
    directory().reference(id).then_some(ObRef { id })
}

/// The object the current process's `handle` names, referenced, when it is of `kind` (any kind
/// for none). None for a handle naming nothing, another kind of object, or a record that is not an
/// object (Windows reports them alike, an invalid handle).
#[cfg(target_arch = "x86")]
pub fn reference_by_handle(handle: u32, kind: Option<ObjectType>) -> Option<ObRef> {
    let id = crate::process::current()
        .handles()
        .lookup(handle)
        .and_then(|entry| entry.object_id())
        .filter(|id| kind.is_none_or(|kind| id.kind == kind))?;
    reference(id)
}

/// Drop a reference on `id` (the last one deletes the object, the current process finishing what
/// the deletion leaves it).
#[cfg(target_arch = "x86")]
pub fn release(id: ObjectId) {
    if let Some(followup) = directory().dereference(id, crate::sched::idle::dispatcher()) {
        crate::user::args::calling_process().finish(followup);
    }
}

/// Publish a new object: a handle to it in `process` (the current one) with `access` and
/// `inheritance`, its name bound, and its creator's reference dropped — the handle holds it from
/// now on. A failure takes the object back with it (none: the table or the names are full).
#[cfg(target_arch = "x86")]
pub fn publish(
    process: &mut crate::process::Process,
    id: ObjectId,
    access: u32,
    inherit: bool,
    name: Option<&[u8]>,
) -> Option<u32> {
    let handle = process.insert_object(id, access, inherit);
    if handle == 0 {
        release(id);
        return None;
    }
    let bound = name.is_none_or(|name| directory().bind_name(name, id).is_ok());
    release(id);
    if !bound {
        process.close_handle(handle);
        return None;
    }
    Some(handle)
}

/// Open the object `id` names as a new handle in `process`; null when the table is full.
#[cfg(target_arch = "x86")]
pub fn open(
    process: &mut crate::process::Process,
    id: ObjectId,
    access: u32,
    inherit: bool,
) -> u32 {
    process.insert_object(id, access, inherit)
}

/// The thread object of the running thread, if it is a pooled thread (every thread that runs a
/// service is).
#[cfg(target_arch = "x86")]
pub fn current_thread() -> Option<ObjectId> {
    directory().thread_id_of(crate::sched::idle::dispatcher().current_thread())
}

/// The running thread's record index in the thread pool.
#[cfg(target_arch = "x86")]
fn current_thread_index() -> u16 {
    current_thread()
        .expect("a service runs on a pooled thread")
        .index
}

/// Wait on `objects` for the running thread: each is referenced for the wait's whole life —
/// replays after an APC included — and released when `wait` returns. A thread that ends inside the
/// wait releases them on its way out ([`end_thread_references`]).
#[cfg(target_arch = "x86")]
pub fn waiting<R>(objects: &[ObjectId], wait: impl FnOnce() -> R) -> R {
    let index = current_thread_index();
    directory().hold_wait(index, objects);
    let result = wait();
    release_wait(index);
    result
}

#[cfg(target_arch = "x86")]
fn release_wait(index: u16) {
    directory().release_wait(index, crate::sched::idle::dispatcher(), |followup| {
        crate::user::args::calling_process().finish(followup)
    });
}

/// A thread has ended (its record is Terminated): its wait's references, if it ended inside one,
/// and the thread's own reference on its object go. Its record is free once nothing else holds it.
#[cfg(target_arch = "x86")]
pub fn end_thread_references(thread: *const Thread) {
    let Some(id) = directory().thread_id_of(thread) else {
        return;
    };
    release_wait(id.index);
    release(id);
}

#[cfg(test)]
mod tests {
    //! The object manager's pure core: counts, generations, names, the waits' references, and the
    //! kinds' teardowns, over a directory of the tests' own.

    use super::*;

    // The rig: leaked records at their final addresses, as the scheduler's test modules build them.

    fn directory() -> &'static mut Directory {
        let mut directory = Box::<Directory>::new_uninit();
        // SAFETY: the box is valid, aligned and the records' final address once leaked.
        unsafe { Directory::write_empty(directory.as_mut_ptr()) };
        // SAFETY: written whole just above.
        Box::leak(unsafe { directory.assume_init() })
    }

    fn dispatcher() -> &'static mut Dispatcher {
        let d = Box::leak(Box::new(Dispatcher::zeroed()));
        d.init();
        d
    }

    fn thread() -> &'static mut Thread {
        let process = Box::leak(Box::new(crate::sched::process::SchedProcess::new(
            0x0090_0000,
            8,
        )));
        process.init();
        let thread = Box::leak(Box::new(Thread::empty()));
        // SAFETY: both are leaked at their final addresses.
        unsafe { thread.attach_to(process) };
        thread
    }

    /// Close a handle to `id`, collecting what the caller must finish.
    fn closed(
        directory: &mut Directory,
        id: ObjectId,
        dispatcher: &mut Dispatcher,
    ) -> Vec<Followup> {
        let mut followups = Vec::new();
        directory.handle_closed(id, dispatcher, |followup| followups.push(followup));
        followups
    }

    /// A published object, as a create leaves it: one handle, the creator's reference dropped.
    fn published(directory: &mut Directory, id: ObjectId, dispatcher: &mut Dispatcher) {
        assert!(directory.handle_opened(id));
        assert_eq!(directory.dereference(id, dispatcher), None);
    }

    /// An object lives as long as anything references it: its creator's reference and each handle's
    /// count, the last reference deletes it, and its id goes stale with it.
    #[test]
    fn an_object_lives_while_referenced() {
        let directory = directory();
        let dispatcher = dispatcher();
        let id = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        assert_eq!(
            directory.counts(id),
            Some((1, 0)),
            "the creator's reference"
        );
        assert!(directory.handle_opened(id));
        assert_eq!(directory.counts(id), Some((2, 1)));
        assert_eq!(directory.dereference(id, dispatcher), None);
        assert_eq!(directory.counts(id), Some((1, 1)), "the handle holds it");
        assert!(directory.reference(id));
        assert_eq!(closed(directory, id, dispatcher), vec![]);
        assert!(
            directory.is_live(id),
            "a reference outlives the last handle"
        );
        assert_eq!(directory.dereference(id, dispatcher), None);
        assert!(!directory.is_live(id), "the last reference deletes it");
        assert_eq!(directory.event(id).map(|_| ()), None);
        assert!(!directory.reference(id), "a stale id names nothing");
        assert!(!directory.handle_opened(id));
    }

    /// A deleted object's record is reused under a new generation: the old id never resolves to the
    /// new object (a wait replayed on the old id cannot land on it).
    #[test]
    fn a_reused_record_has_a_new_generation() {
        let directory = directory();
        let dispatcher = dispatcher();
        let first = directory.create_semaphore(0, 1).unwrap();
        assert_eq!(directory.dereference(first, dispatcher), None);
        let second = directory.create_semaphore(3, 5).unwrap();
        assert_eq!(first.index, second.index, "the record is reused");
        assert_ne!(first.generation, second.generation);
        assert!(directory.semaphore(first).is_none());
        assert_eq!(directory.semaphore(second).unwrap().count(), 3);
        assert!(directory.waitable(first).is_none());
    }

    /// The kinds do not mix: an id resolves only through its own kind's accessors.
    #[test]
    fn ids_resolve_only_as_their_kind() {
        let directory = directory();
        let event = directory
            .create_event(EventKind::Synchronization, true)
            .unwrap();
        let semaphore = directory.create_semaphore(1, 1).unwrap();
        assert!(directory.event(event).is_some());
        assert!(directory.semaphore(event).is_none());
        assert!(directory.event(semaphore).is_none());
        assert!(directory.thread(event).is_none() && directory.process(event).is_none());
        assert!(directory.waitable(event).is_some() && directory.waitable(semaphore).is_some());
    }

    /// A name binds a live object, compares exactly, and goes with the object's last handle — even
    /// while a reference (a wait) keeps the object itself alive.
    #[test]
    fn a_name_goes_with_the_last_handle() {
        let directory = directory();
        let dispatcher = dispatcher();
        let id = directory.create_semaphore(0, 1).unwrap();
        published(directory, id, dispatcher);
        directory.bind_name(b"F2K.sync.semaphore", id).unwrap();
        assert_eq!(directory.lookup_name(b"F2K.sync.semaphore"), Some(id));
        assert_eq!(
            directory.lookup_name(b"f2k.sync.semaphore"),
            None,
            "case-sensitive"
        );
        assert_eq!(directory.lookup_name(b"F2K.sync"), None);
        assert!(directory.reference(id));
        assert_eq!(closed(directory, id, dispatcher), vec![]);
        assert!(directory.is_live(id));
        assert_eq!(
            directory.lookup_name(b"F2K.sync.semaphore"),
            None,
            "the last handle took the name"
        );
        // The name is free for another object.
        let other = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        directory.bind_name(b"F2K.sync.semaphore", other).unwrap();
        assert_eq!(directory.lookup_name(b"F2K.sync.semaphore"), Some(other));
    }

    /// The name table refuses an over-long name and fills at its capacity.
    #[test]
    fn the_name_table_bounds() {
        let directory = directory();
        let id = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        assert_eq!(
            directory.bind_name(&[b'x'; MAX_NAME + 1], id),
            Err(NameError::TooLong)
        );
        for index in 0..NAMES {
            directory
                .bind_name(format!("n{index}").as_bytes(), id)
                .unwrap();
        }
        assert_eq!(directory.bind_name(b"one more", id), Err(NameError::Full));
    }

    /// An object whose last handle closes while a thread waits on it stays live — the wait holds
    /// it — and the wait's return releases it: the object is deleted (a timer would leave the timer
    /// table) only then.
    #[test]
    fn a_wait_holds_its_object_through_its_last_handle() {
        let directory = directory();
        let dispatcher = dispatcher();
        let waiter = directory.create_thread_in(1..THREADS).unwrap();
        let event = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        published(directory, event, dispatcher);

        directory.hold_wait(waiter.index, &[event]);
        assert_eq!(directory.counts(event), Some((2, 1)));
        assert_eq!(
            closed(directory, event, dispatcher),
            vec![],
            "the program closes its handle"
        );
        assert!(directory.is_live(event), "the wait holds it");
        assert!(
            directory.waitable(event).is_some(),
            "still waitable for its waiter"
        );

        let mut followups = Vec::new();
        directory.release_wait(waiter.index, dispatcher, |followup| {
            followups.push(followup)
        });
        assert!(followups.is_empty());
        assert!(
            !directory.is_live(event),
            "the wait's return released the last reference"
        );
    }

    /// A timer whose last handle closes while a thread waits on it stays armed — the wait holds
    /// it — and the wait's return releases it: the timer leaves the timer table only then.
    #[test]
    fn a_wait_holds_a_timer_through_its_last_handle() {
        let directory = directory();
        let dispatcher = dispatcher();
        let waiter = directory.create_thread_in(1..THREADS).unwrap();
        let timer = directory.create_timer(true).unwrap();
        published(directory, timer, dispatcher);
        let record = directory.timer(timer).unwrap();
        dispatcher.set_waitable_timer(record, 1_000_000, 0, 0, false, 0);
        assert!(directory.timer(timer).unwrap().armed());

        directory.hold_wait(waiter.index, &[timer]);
        assert_eq!(directory.counts(timer), Some((2, 1)));
        assert_eq!(
            closed(directory, timer, dispatcher),
            vec![],
            "the program closes its handle"
        );
        assert!(directory.is_live(timer), "the wait holds it");
        assert!(
            directory.timer(timer).unwrap().armed(),
            "still armed for its waiter"
        );

        let mut followups = Vec::new();
        directory.release_wait(waiter.index, dispatcher, |followup| {
            followups.push(followup)
        });
        assert!(followups.is_empty());
        assert!(
            !directory.is_live(timer),
            "the wait's return released the last reference"
        );
        assert!(
            !directory.timers.record(timer.index).armed(),
            "deletion cancelled it"
        );
    }

    /// A timer the process's end sweeps (a leaked reference) leaves the timer table with it.
    #[test]
    fn the_process_end_disarms_a_leaked_timer() {
        let directory = directory();
        let dispatcher = dispatcher();
        let leaked = directory.create_timer(true).unwrap();
        dispatcher.set_waitable_timer(directory.timer(leaked).unwrap(), 1_000_000, 0, 0, false, 0);
        assert_eq!(directory.process_ended(dispatcher, |_| {}), 1);
        assert!(
            !directory.timers.record(leaked.index).armed(),
            "the leaked timer left the table"
        );
    }

    /// A wait's references keep its objects from being recycled while the waiter is away (a
    /// suspend unwinds the wait, which replays later): the record cannot go to a new object.
    #[test]
    fn a_waits_references_keep_records_from_reuse() {
        let directory = directory();
        let dispatcher = dispatcher();
        let waiter = directory.create_thread_in(1..THREADS).unwrap();
        let semaphore = directory.create_semaphore(0, 1).unwrap();
        published(directory, semaphore, dispatcher);
        directory.hold_wait(waiter.index, &[semaphore]);
        assert_eq!(closed(directory, semaphore, dispatcher), vec![]);
        let fresh = directory.create_semaphore(1, 1).unwrap();
        assert_ne!(
            fresh.index, semaphore.index,
            "the held record is not handed out"
        );
        assert!(
            directory.semaphore(semaphore).is_some(),
            "the waiter's object is still its own"
        );
        directory.release_wait(waiter.index, dispatcher, |_| {});
        assert!(!directory.is_live(semaphore));
    }

    /// A wait over several objects holds each, the same object twice twice.
    #[test]
    fn a_wait_holds_every_object_it_names() {
        let directory = directory();
        let dispatcher = dispatcher();
        let waiter = directory.create_thread_in(1..THREADS).unwrap();
        let a = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let b = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        directory.hold_wait(waiter.index, &[a, b, a]);
        assert_eq!(directory.counts(a), Some((3, 0)));
        assert_eq!(directory.counts(b), Some((2, 0)));
        directory.release_wait(waiter.index, dispatcher, |_| {});
        assert_eq!(
            directory.counts(a),
            Some((1, 0)),
            "back to the creators' references"
        );
        assert_eq!(directory.counts(b), Some((1, 0)));
    }

    /// Thread records: created threads never take the main thread's record, the pool exhausts at
    /// its capacity, and a record's pointer resolves to its object.
    #[test]
    fn thread_records_and_their_ranges() {
        let directory = directory();
        let dispatcher = dispatcher();
        let main = directory.create_thread_in(0..1).unwrap();
        assert_eq!(main.index, 0);
        assert_eq!(directory.create_thread_in(0..1), None, "one main thread");
        let mut created = Vec::new();
        while let Some(id) = directory.create_thread_in(1..THREADS) {
            assert_ne!(id.index, 0);
            created.push(id);
        }
        assert_eq!(created.len(), THREADS - 1);
        let last = *created.last().unwrap();
        let record: *const Thread = directory.threads.record(last.index);
        assert_eq!(directory.thread_id_of(record), Some(last));
        assert_eq!(
            directory.thread_id_of(core::ptr::null()),
            None,
            "not a pool record"
        );
        // A thread's own reference released: its record is free again.
        assert_eq!(directory.dereference(last, dispatcher), None);
        assert_eq!(directory.thread_id_of(record), None);
        assert_eq!(
            directory.create_thread_in(1..THREADS).map(|id| id.index),
            Some(last.index)
        );
    }

    /// The pools refuse past their capacity.
    #[test]
    fn the_pools_exhaust() {
        let directory = directory();
        for _ in 0..SEMAPHORES {
            assert!(directory.create_semaphore(0, 1).is_some());
        }
        assert_eq!(directory.create_semaphore(0, 1), None);
        assert_eq!(directory.live_objects(), SEMAPHORES);
    }

    /// A deleted mutex its owner still held leaves the owner's list: the owner's end then has
    /// nothing of it to abandon.
    #[test]
    fn a_deleted_owned_mutex_leaves_its_owner() {
        let directory = directory();
        let dispatcher = dispatcher();
        let owner = thread();
        let id = directory.create_mutex().unwrap();
        crate::sched::mutex::acquire(directory.mutex(id).unwrap(), owner);
        assert!(!owner.owned_mutexes.is_empty());
        assert!(directory.waitable(id).is_some(), "a mutex is waitable");
        assert_eq!(directory.dereference(id, dispatcher), None);
        assert!(owner.owned_mutexes.is_empty(), "the deletion unlinked it");
        dispatcher.abandon_mutexes(owner);
    }

    /// `\BaseNamedObjects` is made once, at its first need, and is permanent: no process's end
    /// deletes it, nor counts it as a leak; no wait can name it.
    #[test]
    fn the_named_objects_directory_is_permanent() {
        let directory = directory();
        let dispatcher = dispatcher();
        let id = directory.named_objects().unwrap();
        assert_eq!(directory.named_objects(), Some(id), "one directory");
        assert_eq!(directory.waitable(id), None);
        // An open's handle, then its close: the creator's reference stays.
        assert!(directory.handle_opened(id));
        assert_eq!(closed(directory, id, dispatcher), vec![]);
        assert_eq!(directory.counts(id), Some((1, 0)));
        assert_eq!(directory.process_ended(dispatcher, |_| {}), 0);
        assert!(directory.is_live(id), "it outlives every process");
        assert_eq!(directory.named_objects(), Some(id));
    }

    /// The process's end deletes whatever outlived it (a reference leak, reported) and starts every
    /// thread record and name over.
    #[test]
    fn the_process_end_sweeps_the_directory() {
        let directory = directory();
        let dispatcher = dispatcher();
        let leaked = directory
            .create_event(EventKind::Notification, true)
            .unwrap();
        directory.bind_name(b"left", leaked).unwrap();
        let main = directory.create_thread_in(0..1).unwrap();
        directory.threads.record(main.index).teb_va = 0x0031_0000;
        assert_eq!(directory.process_ended(dispatcher, |_| {}), 2);
        assert_eq!(directory.live_objects(), 0);
        assert!(!directory.is_live(leaked));
        assert_eq!(directory.lookup_name(b"left"), None);
        assert_eq!(
            directory.threads.record(main.index).teb_va(),
            0,
            "records start over"
        );
    }

    /// One namespace for every kind and both session prefixes: `Global\` and `Local\` name the same
    /// object as the bare name, and a name binds one object whatever kind asks.
    #[test]
    fn the_namespace_is_one_directory() {
        let directory = directory();
        let dispatcher = dispatcher();
        let event = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        published(directory, event, dispatcher);
        directory.bind_name(b"Global\\F2K.ready", event).unwrap();
        assert_eq!(directory.lookup_name(b"F2K.ready"), Some(event));
        assert_eq!(directory.lookup_name(b"Local\\F2K.ready"), Some(event));
        assert_eq!(directory.lookup_name(b"Global\\F2K.ready"), Some(event));
        assert_eq!(
            directory.lookup_name(b"global\\F2K.ready"),
            None,
            "the prefix as spelled"
        );
        // Another kind finds the same binding: its create sees a kind mismatch.
        let found = directory.lookup_name(b"F2K.ready").unwrap();
        assert_eq!(found.kind, ObjectType::Event);
        assert_eq!(
            namespace_name(b"Local\\"),
            b"",
            "a bare prefix names nothing"
        );
        assert_eq!(namespace_name(b"Session\\1"), b"Session\\1");
    }

    /// A process object: waitable, still active and unsignaled until its end, signaled with its
    /// exit code at the end; the process-end sweep leaves it to its own reference, whose
    /// release frees the record for the next process; the pool's capacity is the process
    /// pool's.
    #[test]
    fn a_process_object_signals_its_end() {
        let directory = directory();
        let dispatcher = dispatcher();
        let id = directory.create_process().unwrap();
        assert_eq!(directory.processes_live(id.index), Some(id));
        assert_eq!(
            directory.process(id).map(|process| process.exit_status),
            Some(STILL_ACTIVE)
        );
        let waitable = directory.waitable(id).expect("a process is waitable");
        // SAFETY: the live process object's waitable.
        assert_eq!(unsafe { (*waitable).signal_state() }, 0);
        // A handle to it and the process's own reference.
        assert!(directory.handle_opened(id));
        assert_eq!(
            directory.process_ended(dispatcher, |_| {}),
            0,
            "a process object is no leak"
        );
        assert!(directory.is_live(id));
        directory.signal_process_end(id, 3, dispatcher);
        // SAFETY: as above.
        assert_eq!(unsafe { (*waitable).signal_state() }, 1);
        assert_eq!(
            directory.process(id).map(|process| process.exit_status),
            Some(3)
        );
        assert_eq!(
            directory.dereference(id, dispatcher),
            None,
            "the process's own reference goes"
        );
        assert!(
            directory.is_live(id),
            "the handle still names the ended process"
        );
        assert_eq!(closed(directory, id, dispatcher), vec![]);
        assert_eq!(
            directory.processes_live(id.index),
            None,
            "the record is free"
        );
        let ids: Vec<_> = (0..PROCESSES)
            .map(|_| directory.create_process().unwrap())
            .collect();
        assert_eq!(ids[0].index, id.index, "the lowest free record is reused");
        assert!(
            directory.create_process().is_none(),
            "the pool is the process pool's size"
        );
    }

    /// A handle-table entry names an object by its id (an open file's is its file object).
    #[test]
    fn entries_name_objects() {
        let id = ObjectId {
            kind: ObjectType::Event,
            index: 3,
            generation: 7,
        };
        let entry = Entry::object(id, EVENT_ALL_ACCESS, true);
        assert_eq!(entry.object_id(), Some(id));
        assert!(entry.inherit);
        let file = ObjectId {
            kind: ObjectType::File,
            index: 2,
            generation: 0,
        };
        assert_eq!(
            Entry::object(file, 0x0012_0089, false).object_id(),
            Some(file)
        );
    }

    /// A section is no waitable; its deletion hands its frames (and a file's section its file
    /// object) back to the caller, a view's reference keeping it past its last handle, and its
    /// record starts over.
    #[test]
    fn a_deleted_section_hands_back_its_frames() {
        let directory = directory();
        let dispatcher = dispatcher();
        let file_object = ObjectId {
            kind: ObjectType::File,
            index: 2,
            generation: 5,
        };
        let section = SectionObject {
            size: 3,
            paging_file: false,
            file_object: Some(file_object),
            ..SectionObject::none()
        };
        let id = directory.create_section(section).unwrap();
        assert_eq!(directory.waitable(id), None, "a section is not waitable");
        assert_eq!(directory.section(id).map(|section| section.size), Some(3));
        published(directory, id, dispatcher);
        // A view's reference keeps it past its handle.
        assert!(directory.reference(id));
        assert_eq!(closed(directory, id, dispatcher), vec![]);
        assert_eq!(
            directory.dereference(id, dispatcher),
            Some(Followup::Section {
                frames: crate::mem::vm::SectionFrames::empty(),
                file_object: Some(file_object),
            })
        );
        assert_eq!(
            directory.sections.record(id.index).size,
            0,
            "the record holds no mapping any more"
        );
    }

    /// A file object's last handle is its cleanup (share access, delete-on-close), and its last
    /// reference its close: a mapping's reference holds it between the two. It is no waitable.
    #[test]
    fn a_file_object_cleans_up_then_closes() {
        let directory = directory();
        let dispatcher = dispatcher();
        let id = directory
            .create_file(
                4,
                crate::fs::file::ACCESS_READ,
                0x8000_0000,
                crate::fs::file::SHARE_ALL,
            )
            .unwrap();
        assert_eq!(
            directory.waitable(id),
            None,
            "a file object is not waitable"
        );
        directory.file(id).unwrap().delete_on_close = true;
        published(directory, id, dispatcher);
        assert!(directory.handle_opened(id), "a duplicate");
        assert_eq!(
            closed(directory, id, dispatcher),
            vec![],
            "another handle remains"
        );
        assert!(directory.reference(id), "a section's");
        assert_eq!(
            closed(directory, id, dispatcher),
            vec![Followup::FileCleanup {
                record: 4,
                access: 1,
                share: 7,
                delete_on_close: true,
                search: 0
            }]
        );
        assert_eq!(
            directory.dereference(id, dispatcher),
            Some(Followup::FileClose { record: 4 })
        );
        // Both at once when nothing else holds it.
        let id = directory.create_file(5, 0, 0x80, 0).unwrap();
        published(directory, id, dispatcher);
        assert_eq!(
            closed(directory, id, dispatcher),
            vec![
                Followup::FileCleanup {
                    record: 5,
                    access: 0,
                    share: 0,
                    delete_on_close: false,
                    search: 0
                },
                Followup::FileClose { record: 5 },
            ]
        );
    }
}
