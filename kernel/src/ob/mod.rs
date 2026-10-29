//! The object manager: every kernel object a handle can name, with its lifetime.
//!
//! Objects live in typed pools of fixed capacity, global to the kernel rather than to a process:
//! every process's objects share them, and a process's end deletes only what its own references
//! held (the leak sweep waits for quiescence, when no process is left to hold one). An object
//! is named by an [`ObjectId`] — its kind, its pool index and the generation of that record — never
//! by a raw pointer: the generation moves on when the object is deleted, so an id that outlived its
//! object resolves to nothing instead of to whatever reused the record.
//!
//! The dispatcher objects — events, semaphores, mutexes, waitable timers, threads, and the
//! waitable side of processes — keep only their headers here: their bodies are records of the
//! dispatcher database ([`crate::sched::database`]), at the same index, as Windows 2000 keeps a
//! dispatcher object's DISPATCHER_HEADER and type fields apart from its object header. An id names
//! its body there by that index ([`ObjectId::waitable`]), where the body is reached with the
//! dispatch token; the directory itself holds no token, so what it does to a body (a create's
//! fresh body, a deletion's cancel) it does raised to the dispatch level.
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
//! # The directory's lock
//!
//! The kernel's directory is passive-level state behind a short lock (Windows 2000's object
//! manager guards its namespace and object headers with a fast mutex too): [`lock`] takes it with
//! the caller's passive token, which the guard keeps borrowed, and [`locked`] is the bridge for
//! code that holds no token. The lock is held briefly and never across a wait, a user-memory copy
//! or disk I/O. So a deletion does not finish its object's teardown in place: what lies outside
//! the directory — a section's frames, a file object's cleanup (which may delete the file, on disk)
//! and its close — comes back as a [`Followup`], which the caller finishes with [`finish`] once the
//! lock is released, as Windows 2000 runs an object's delete procedure after the object-manager
//! lock is dropped. A look-up and what it decides (a name's binding and the create it allows, a
//! handle's object and the reference that keeps it) happen in one hold, so no other thread comes
//! between them.
//!
//! A kind plugs in with its row in the pools' table ([`Directory`]), a `create_*`, and — when its
//! deletion needs more than the record going dead (a timer leaving the timer table, an owned mutex
//! its owner's list) — an arm in `delete`; a kind whose body the directory holds gets its typed
//! accessor from the bodies' table; what the deletion leaves outside the directory is a
//! [`Followup`] variant.
//!
//! The capacities are fixed (a create past them fails as the platform's out-of-memory would).

use rtl::array_vec::ArrayVec;

use crate::level::Dispatch;
use crate::sched::dispatcher::Dispatcher;
use crate::sched::event::EventKind;
use crate::sched::mutex::MutexId;
use crate::sched::thread::ThreadId;
use crate::sched::timer::TimerId;
use crate::sched::wait::{WaitableId, MAXIMUM_WAIT_OBJECTS};

/// Run `f` on the dispatcher database, where the dispatcher objects' bodies live: the kernel's one
/// dispatcher (on the host, the test thread's). The directory holds no token: it raises to the
/// dispatch level for the length of `f` (the level bridge), so it is never reached from there.
fn with_bodies<R>(f: impl FnOnce(&mut Dispatcher) -> R) -> R {
    crate::level::raised::<Dispatch, _>(|dispatch| f(crate::sched::DISPATCHER.get(dispatch)))
}

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
    /// A window station: win32k's, WinSta0 the one there is (permanent: made at boot; see
    /// [`crate::win32k`]).
    WindowStation,
    /// A desktop of a window station: WinSta0's Default, the one there is (permanent: made at
    /// boot).
    Desktop,
    /// A key object: one open of a registry key (see [`crate::cm`]).
    Key,
}

/// An object's identity: its kind, its record in that kind's pool, and the record's generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ObjectId {
    pub kind: ObjectType,
    pub index: u16,
    pub generation: u16,
}

impl ObjectId {
    /// The waitable name of a dispatcher object's body (an event, a semaphore, a mutex, a waitable
    /// timer, a thread, a process), as the wait entries take it: the dispatcher database's record
    /// at the object's own index. None for a section, a file object (its I/O completes at once:
    /// nothing waits on it), the directory, a window station, a desktop or a key. The id's
    /// liveness is the caller's to know (a reference it holds).
    pub fn waitable(self) -> Option<WaitableId> {
        let index = self.index;
        match self.kind {
            ObjectType::Event => Some(WaitableId::Event(index)),
            ObjectType::Semaphore => Some(WaitableId::Semaphore(index)),
            ObjectType::Mutex => Some(WaitableId::Mutex(index)),
            ObjectType::Timer => Some(WaitableId::Timer(index)),
            ObjectType::Thread => Some(WaitableId::Thread(ThreadId(index))),
            ObjectType::Process => Some(WaitableId::Process(index)),
            ObjectType::Section
            | ObjectType::File
            | ObjectType::Directory
            | ObjectType::WindowStation
            | ObjectType::Desktop
            | ObjectType::Key => None,
        }
    }

    /// The body index of a dispatcher object of `kind`; none for an id of another kind.
    fn body_of(self, kind: ObjectType) -> Option<u16> {
        (self.kind == kind).then_some(self.index)
    }
}

/// What a handle-table entry names: an object (a directory search is kernel32's own structure on
/// the process heap, as on Windows 2000, not a kernel handle).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    Object(ObjectId),
}

/// One handle-table entry: what the handle names, the access it was granted, whether a child
/// process would inherit it, and whether it is protected from close (NtSetInformationObject's
/// ObjectHandleFlagInformation: NtClose refuses it).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub target: Target,
    pub access: u32,
    pub inherit: bool,
    pub protect_from_close: bool,
}

impl Entry {
    /// An entry naming an object (not protected from close: a handle is made closable).
    pub fn object(id: ObjectId, access: u32, inherit: bool) -> Self {
        Entry {
            target: Target::Object(id),
            access,
            inherit,
            protect_from_close: false,
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
pub const SECTIONS: usize = 32;
/// How many image segments can exist at once: one per image file mapped (see [`ImageSegment`]).
pub const SEGMENTS: usize = 16;
/// How many file objects can exist at once.
pub const FILES: usize = crate::fs::file::OPEN_FILES;
/// How many thread records exist, across every process: any process's thread takes any free
/// record, main thread or created. A record's index is not its thread's ordinal (the process's own
/// numbering, which places its TEB: see [`crate::process::ordinals`]). Room for two processes at
/// nearly their full thread counts.
pub const THREADS: usize = 128;
/// How many processes can exist at once: the process pool's records ([`crate::process::pool`]),
/// one process object each.
pub const PROCESSES: usize = crate::process::MAX_PROCESSES;
/// How many object directories exist: `\BaseNamedObjects`, the named objects' (permanent: made
/// at its first open, it is never deleted).
pub const DIRECTORIES: usize = 1;
/// How many window stations exist: WinSta0, the interactive one (permanent: made at boot).
pub const WINDOW_STATIONS: usize = 1;
/// How many desktops exist: WinSta0's Default (permanent: made at boot).
pub const DESKTOPS: usize = 1;
/// How many key objects (opens of registry keys) can exist at once.
pub const KEY_OBJECTS: usize = 256;
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

    /// Whether the header holds the live object of `generation`.
    fn names(&self, generation: u16) -> bool {
        self.live && self.generation == generation
    }
}

/// Take a free record among `headers` in `range` for a new object: the lowest one holding no live
/// object. The object starts with one reference (its creator's) and no handle. None when the range
/// is exhausted. The record itself is the caller's to renew.
fn allocate(headers: &mut [Header], range: core::ops::Range<usize>) -> Option<u16> {
    let end = range.end.min(headers.len());
    let index = (range.start..end).find(|&index| !headers[index].live)?;
    let header = &mut headers[index];
    header.live = true;
    header.pointers = 1;
    header.handles = 0;
    Some(index as u16)
}

/// A fixed pool of records of one kind, each behind its header. Records stay at their addresses for
/// the kernel's life (a file object's lock event is named by its address). The dispatcher objects'
/// pools hold headers alone (`T` is `()`): their bodies are the dispatcher database's.
pub struct Pool<T, const N: usize> {
    headers: [Header; N],
    records: [T; N],
}

impl<T, const N: usize> Pool<T, N> {
    /// Write an empty pool at `pool`, every record `fresh()`, element by element (by value it would
    /// pass through the caller's stack).
    ///
    /// # Safety
    ///
    /// `pool` is valid for writes and aligned; its previous contents are overwritten, not dropped.
    unsafe fn write_empty(pool: *mut Self, fresh: impl Fn() -> T) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written.
        unsafe {
            let headers = addr_of_mut!((*pool).headers) as *mut Header;
            let records = addr_of_mut!((*pool).records) as *mut T;
            for index in 0..N {
                headers.add(index).write(Header::dead());
                records.add(index).write(fresh());
            }
        }
    }

    /// Take a free record in `range` for a new object (see [`allocate`]).
    fn allocate_in(&mut self, range: core::ops::Range<usize>) -> Option<u16> {
        allocate(&mut self.headers, range)
    }

    /// Whether the record at `index` holds a live object.
    fn is_live_at(&self, index: u16) -> bool {
        self.headers[index as usize].live
    }

    /// How many records hold a live object.
    #[cfg(test)]
    fn live(&self) -> usize {
        self.headers.iter().filter(|header| header.live).count()
    }
}

/// A section object's body: the mapping itself. A data section is its own segment: its frames are
/// its own, and a view names it by its object, so its frames outlive the handle that made it while
/// a view references it. An image section is a section of its file's one [`ImageSegment`]: it
/// holds the segment, and its views hold the segment, not the section.
#[derive(Clone, Copy)]
pub struct SectionObject {
    /// The mapped file, as its open found it (a file-backed section).
    pub file: crate::fs::fat32::lookup::File,
    /// Whether it is the paging file's (its pages start zeroed) rather than a file's.
    pub paging_file: bool,
    /// Whether a paging-file section was created SEC_RESERVE rather than SEC_COMMIT, as
    /// NtQuerySection reports it (its views' pages are made as they are touched all the same).
    pub reserve: bool,
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
    /// An image section's segment, which it holds a reference on (none: a data section).
    pub segment: Option<SegmentId>,
}

impl SectionObject {
    /// A record holding no mapping (a pool's fresh record).
    pub const fn none() -> Self {
        SectionObject {
            file: crate::fs::fat32::lookup::File::plain(0, 0, false),
            paging_file: true,
            reserve: false,
            frames: crate::mem::vm::SectionFrames::empty(),
            size: 0,
            writable: false,
            file_object: None,
            image_base: 0,
            segment: None,
        }
    }
}

/// An image segment: an image file's pages as mapped, shared by every image section of the file
/// and every view of them (NT's image control area and segment). A file has at most one, reached
/// from its record ([`crate::fs::file::FileRecord::image`], NT's section object pointers): the
/// first image section of the file makes it, and later ones share it, so every process's view of a
/// DLL maps the same frames (its writable pages copy-on-write). It holds the file object it was
/// made from — the file stays open, counted as mapped, while it lives — and lives while an image
/// section or a view references it; its last reference gives its frames and its file back.
#[derive(Clone, Copy)]
pub struct ImageSegment {
    /// Its frames, page by page, made as views first need them.
    pub frames: crate::mem::vm::SectionFrames,
    /// The file object it holds.
    pub file_object: ObjectId,
    /// The image's preferred base, where every view maps it.
    pub image_base: u32,
    /// The image's size as mapped.
    pub size: u32,
}

impl ImageSegment {
    /// A record holding no segment (a pool's fresh record).
    const fn none() -> Self {
        ImageSegment {
            frames: crate::mem::vm::SectionFrames::empty(),
            file_object: ObjectId {
                kind: ObjectType::File,
                index: 0,
                generation: 0,
            },
            image_base: 0,
            size: 0,
        }
    }
}

/// An image segment's name: its pool index and the generation of that record, so a name that
/// outlived its segment (a file record's, once the segment went) resolves to nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SegmentId {
    pub index: u16,
    pub generation: u16,
}

/// What a mapped view maps, and holds a reference on for as long as it is mapped: a data section,
/// or an image segment (the image section that made the view may be closed at once).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mapping {
    Section(ObjectId),
    Image(SegmentId),
}

/// A window station's body: its name (the window station's own, as GetUserObjectInformation's
/// UOI_NAME reports it; not bound in the namespace) and its flags (UOI_FLAGS' dwFlags:
/// WSF_VISIBLE for the interactive one).
#[derive(Clone, Copy)]
pub struct WindowStationObject {
    pub name: &'static str,
    pub flags: u32,
}

impl WindowStationObject {
    /// A record holding no window station (a pool's fresh record).
    pub const fn none() -> Self {
        WindowStationObject { name: "", flags: 0 }
    }
}

/// A desktop's body: its name (as UOI_NAME reports it) and its flags (UOI_FLAGS' dwFlags:
/// DF_ALLOWOTHERACCOUNTHOOK or none). There is one window station, so a desktop's is WinSta0.
#[derive(Clone, Copy)]
pub struct DesktopObject {
    pub name: &'static str,
    pub flags: u32,
}

impl DesktopObject {
    /// A record holding no desktop (a pool's fresh record).
    pub const fn none() -> Self {
        DesktopObject { name: "", flags: 0 }
    }
}

/// What a caller must finish once an object's last handle or last reference went: the work outside
/// the object manager's reach, finished once the directory's lock is released ([`finish`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Followup {
    /// A section or an image segment was deleted: its frames (taken out of its record) and the
    /// file object a file's section or a segment held are the caller's to release.
    Section {
        frames: crate::mem::vm::SectionFrames,
        file_object: Option<ObjectId>,
    },
    /// A file object's last handle closed (its cleanup): its share access leaves the file's
    /// record, its delete-on-close marks the file delete-pending, and the last cleanup of a
    /// delete-pending file deletes it.
    FileCleanup {
        record: crate::fs::file::FileRecordId,
        access: u8,
        share: u8,
        delete_on_close: bool,
    },
    /// A file object was deleted: its reference on the file's record goes.
    FileClose {
        record: crate::fs::file::FileRecordId,
    },
}

/// The most follow-ups one handle's close leaves: a file object's cleanup, then what the object's
/// deletion leaves (its close, or a section's frames).
pub const MOST_FOLLOWUPS: usize = 2;

/// The follow-ups one directory operation leaves its caller, in the order they are finished.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct Followups(ArrayVec<Option<Followup>, MOST_FOLLOWUPS>);

impl Followups {
    /// No follow-up.
    pub fn none() -> Self {
        Followups(ArrayVec::new())
    }

    /// `followup` added at the end, when there is one.
    fn push(&mut self, followup: Option<Followup>) {
        if followup.is_some() {
            self.0.push(followup);
        }
    }

    /// The follow-ups, in order.
    pub fn iter(&self) -> impl Iterator<Item = Followup> + '_ {
        self.0.iter().flatten().copied()
    }

    /// Finish every follow-up, in order (see [`finish`]): the directory's lock is released by now.
    #[cfg(target_arch = "x86")]
    pub fn finish(self) {
        for followup in self.iter() {
            finish(followup);
        }
    }
}

/// One object or image segment the sweep at quiescence deleted ([`Directory::sweep_next`]), with
/// what its deletion leaves.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Leak {
    pub followup: Option<Followup>,
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

/// The kinds' pools, one row each: the kind, its pool's field, its body (`()` for a dispatcher
/// object: the body is the dispatcher database's, at the same index; a process keeps its thread
/// ordinals here, since which of them are free is its thread objects' lives), how a fresh record is
/// made, and the capacity. The table makes the [`Directory`]'s pools, its in-place builder, and the
/// one match the untyped paths (a header by id, the counts, the sweep) reach a kind's headers
/// through.
macro_rules! pools {
    ($($kind:ident => $pool:ident: $body:ty = $fresh:expr, $capacity:expr;)*) => {
        /// Every object, by kind, with the image segments, the namespace and the waits'
        /// references. The dispatcher objects' pools are their headers alone: the bodies are the
        /// dispatcher database's, at the same index.
        pub struct Directory {
            $($pool: Pool<$body, $capacity>,)*
            segments: Pool<ImageSegment, SEGMENTS>,
            names: [NameEntry; NAMES],
            waits: [WaitReferences; THREADS],
        }

        impl Directory {
            /// Write an empty directory at `directory`: every pool empty, no names, no waits.
            ///
            /// # Safety
            ///
            /// `directory` is valid for writes, aligned, and the records' final address; its
            /// previous contents are overwritten, not dropped.
            pub unsafe fn write_empty(directory: *mut Directory) {
                use core::ptr::addr_of_mut;
                // SAFETY: the caller's contract; every field is written.
                unsafe {
                    $(Pool::write_empty(addr_of_mut!((*directory).$pool), $fresh);)*
                    Pool::write_empty(addr_of_mut!((*directory).segments), ImageSegment::none);
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

            /// The headers of `kind`'s pool.
            fn headers(&mut self, kind: ObjectType) -> &mut [Header] {
                match kind {
                    $(ObjectType::$kind => &mut self.$pool.headers,)*
                }
            }

            /// How many objects are live, of every kind.
            #[cfg(test)]
            pub fn live_objects(&self) -> usize {
                0 $(+ self.$pool.live())*
            }
        }
    };
}

pools! {
    Event => events: () = || (), EVENTS;
    Semaphore => semaphores: () = || (), SEMAPHORES;
    Mutex => mutexes: () = || (), MUTEXES;
    Timer => timers: () = || (), TIMERS;
    Thread => threads: () = || (), THREADS;
    Process => processes: crate::process::ordinals::Ordinals =
        crate::process::ordinals::Ordinals::empty, PROCESSES;
    Section => sections: SectionObject = SectionObject::none, SECTIONS;
    File => files: crate::fs::file::FileObject = crate::fs::file::FileObject::none, FILES;
    Directory => directories: () = || (), DIRECTORIES;
    WindowStation => window_stations: WindowStationObject = WindowStationObject::none,
        WINDOW_STATIONS;
    Desktop => desktops: DesktopObject = DesktopObject::none, DESKTOPS;
    Key => keys: crate::cm::KeyBody = crate::cm::KeyBody::none, KEY_OBJECTS;
}

// SAFETY: the directory's raw pointers are the links of the file objects' embedded lock headers,
// which name waitable headers and threads of the dispatcher database, reached there only with the
// dispatch token. One processor, and the directory is reached only through its lock, so whichever
// kernel thread holds it is the only one reaching its records.
unsafe impl Send for Directory {}

/// A kind whose body the directory holds (no dispatcher object's): its kind, and its pool's headers
/// and records.
pub trait Body: Sized {
    const KIND: ObjectType;

    /// The kind's pool in `directory`, as its headers and its records.
    fn pool(directory: &mut Directory) -> (&mut [Header], &mut [Self]);
}

/// The bodies' table: each body type, its kind, its pool, and the name of its typed accessor.
macro_rules! bodies {
    ($($body:ty => $kind:ident, $pool:ident, $accessor:ident;)*) => {
        $(
            impl Body for $body {
                const KIND: ObjectType = ObjectType::$kind;

                fn pool(directory: &mut Directory) -> (&mut [Header], &mut [Self]) {
                    (&mut directory.$pool.headers, &mut directory.$pool.records)
                }
            }
        )*

        impl Directory {
            $(
                #[doc = concat!("The live ", stringify!($kind), " object's body `id` names.")]
                pub fn $accessor(&mut self, id: ObjectId) -> Option<&mut $body> {
                    self.body(id)
                }
            )*
        }
    };
}

bodies! {
    crate::process::ordinals::Ordinals => Process, processes, ordinals;
    SectionObject => Section, sections, section;
    crate::fs::file::FileObject => File, files, file;
    WindowStationObject => WindowStation, window_stations, window_station;
    DesktopObject => Desktop, desktops, desktop;
    crate::cm::KeyBody => Key, keys, key;
}

impl Directory {
    fn header(&mut self, id: ObjectId) -> Option<&mut Header> {
        let header = self.headers(id.kind).get_mut(id.index as usize)?;
        header.names(id.generation).then_some(header)
    }

    fn id(&mut self, kind: ObjectType, index: u16) -> ObjectId {
        ObjectId {
            kind,
            index,
            generation: self.headers(kind)[index as usize].generation,
        }
    }

    /// Whether `id` names a live object.
    pub fn is_live(&mut self, id: ObjectId) -> bool {
        self.header(id).is_some()
    }

    /// How many handles name `id`; none for an id that names nothing.
    pub fn handle_count(&mut self, id: ObjectId) -> Option<u32> {
        self.header(id).map(|header| header.handles)
    }

    /// An object's (pointer, handle) counts; none for an id that names nothing.
    #[cfg(test)]
    pub fn counts(&mut self, id: ObjectId) -> Option<(u32, u32)> {
        self.header(id)
            .map(|header| (header.pointers, header.handles))
    }

    /// The body of the live object `id` names, when it is of `T`'s kind.
    pub fn body<T: Body>(&mut self, id: ObjectId) -> Option<&mut T> {
        if id.kind != T::KIND {
            return None;
        }
        let (headers, records) = T::pool(self);
        let header = headers.get(id.index as usize)?;
        header
            .names(id.generation)
            .then(|| &mut records[id.index as usize])
    }

    /// A new object of `T`'s kind holding `body`, with its creator's reference; none when the pool
    /// is exhausted.
    fn insert<T: Body>(&mut self, body: T) -> Option<ObjectId> {
        let (headers, records) = T::pool(self);
        let all = 0..headers.len();
        let index = allocate(headers, all)?;
        records[index as usize] = body;
        Some(self.id(T::KIND, index))
    }

    // --- Creation ----------------------------------------------------------------------------

    /// A fresh event of `kind` at `signaled`, holding its creator's reference; none when the pool
    /// is exhausted.
    pub fn create_event(&mut self, kind: EventKind, signaled: bool) -> Option<ObjectId> {
        let index = self.events.allocate_in(0..EVENTS)?;
        with_bodies(|bodies| {
            bodies.renew_event(index, kind, signaled);
        });
        Some(self.id(ObjectType::Event, index))
    }

    /// A fresh semaphore at `initial` with ceiling `limit`.
    pub fn create_semaphore(&mut self, initial: i32, limit: i32) -> Option<ObjectId> {
        let index = self.semaphores.allocate_in(0..SEMAPHORES)?;
        with_bodies(|bodies| {
            bodies.renew_semaphore(index, initial, limit);
        });
        Some(self.id(ObjectType::Semaphore, index))
    }

    /// A fresh, free mutex.
    pub fn create_mutex(&mut self) -> Option<ObjectId> {
        let index = self.mutexes.allocate_in(0..MUTEXES)?;
        with_bodies(|bodies| {
            bodies.renew_mutex(index);
        });
        Some(self.id(ObjectType::Mutex, index))
    }

    /// A fresh, unarmed, unsignaled waitable timer.
    pub fn create_timer(&mut self, manual_reset: bool) -> Option<ObjectId> {
        let index = self.timers.allocate_in(0..TIMERS)?;
        with_bodies(|bodies| {
            bodies.renew_waitable_timer(index, manual_reset);
        });
        Some(self.id(ObjectType::Timer, index))
    }

    /// A thread record for a new thread object, in `range`. The record is returned as it was left;
    /// the caller renews it ([`Directory::renew_thread`]). Holds the thread's own reference,
    /// released when the thread ends.
    pub fn create_thread_in(&mut self, range: core::ops::Range<usize>) -> Option<ObjectId> {
        let index = self.threads.allocate_in(range)?;
        Some(self.id(ObjectType::Thread, index))
    }

    /// The record of the thread object `id`, started over as fresh as the pool made it: a created
    /// thread's, before its attach. Returns the record's name.
    ///
    /// # Panics
    ///
    /// `id` names no live thread object.
    pub fn renew_thread(&mut self, id: ObjectId) -> ThreadId {
        assert!(
            id.kind == ObjectType::Thread && self.is_live(id),
            "a renewed thread record is a live thread object's"
        );
        let thread = ThreadId(id.index);
        with_bodies(|bodies| {
            bodies.renew_thread(thread);
        });
        thread
    }

    /// A thread record for a new thread object of any process, main thread or created: the lowest
    /// free record of the whole pool (see [`Directory::create_thread_in`]). None when every record
    /// holds a live thread object.
    pub fn create_thread(&mut self) -> Option<ObjectId> {
        self.create_thread_in(0..THREADS)
    }

    /// A process object for a new process, unsignaled and still active, holding the process's own
    /// reference, with every thread ordinal free; none when every process record is in use. Its
    /// index is the process record's.
    pub fn create_process(&mut self) -> Option<ObjectId> {
        let index = self.processes.allocate_in(0..PROCESSES)?;
        self.processes.records[index as usize].reset();
        with_bodies(|bodies| {
            bodies.renew_process_object(index);
        });
        Some(self.id(ObjectType::Process, index))
    }

    /// A section object holding `section` (the mapping).
    pub fn create_section(&mut self, section: SectionObject) -> Option<ObjectId> {
        self.insert(section)
    }

    /// An image segment holding `segment`, with one reference: its creator's (the image section
    /// made with it). None when the pool is exhausted.
    pub fn create_segment(&mut self, segment: ImageSegment) -> Option<SegmentId> {
        let index = self.segments.allocate_in(0..SEGMENTS)?;
        self.segments.records[index as usize] = segment;
        Some(SegmentId {
            index,
            generation: self.segments.headers[index as usize].generation,
        })
    }

    /// The live image segment `id` names.
    pub fn segment(&mut self, id: SegmentId) -> Option<&mut ImageSegment> {
        let header = self.segments.headers.get(id.index as usize)?;
        header
            .names(id.generation)
            .then(|| &mut self.segments.records[id.index as usize])
    }

    /// Take a reference on the image segment `id`; false when it names nothing.
    pub fn reference_segment(&mut self, id: SegmentId) -> bool {
        match self.segment_header(id) {
            Some(header) => {
                header.pointers += 1;
                true
            }
            None => false,
        }
    }

    /// Drop a reference on the image segment `id`; the last one deletes it, its frames and the
    /// file object it held left to the caller.
    pub fn dereference_segment(&mut self, id: SegmentId) -> Option<Followup> {
        let header = self.segment_header(id)?;
        header.pointers -= 1;
        if header.pointers != 0 {
            return None;
        }
        Some(self.delete_segment(id.index))
    }

    /// Delete the image segment at pool `index`: its record is dead and its ids stale.
    fn delete_segment(&mut self, index: u16) -> Followup {
        let segment = core::mem::replace(
            &mut self.segments.records[index as usize],
            ImageSegment::none(),
        );
        let header = &mut self.segments.headers[index as usize];
        header.live = false;
        header.pointers = 0;
        header.generation = header.generation.wrapping_add(1);
        Followup::Section {
            frames: segment.frames,
            file_object: Some(segment.file_object),
        }
    }

    fn segment_header(&mut self, id: SegmentId) -> Option<&mut Header> {
        let header = self.segments.headers.get_mut(id.index as usize)?;
        header.names(id.generation).then_some(header)
    }

    /// A view went: drop its reference on what it mapped (the last one deletes it).
    pub fn release_mapping(&mut self, mapping: Mapping) -> Option<Followup> {
        match mapping {
            Mapping::Section(id) => self.dereference(id),
            Mapping::Image(id) => self.dereference_segment(id),
        }
    }

    /// A file object of file record `record`, opened for `access` (as the share check reads it;
    /// `granted` the file rights) and allowing `share`.
    pub fn create_file(
        &mut self,
        record: crate::fs::file::FileRecordId,
        access: u8,
        granted: u32,
        share: u8,
    ) -> Option<ObjectId> {
        let id = self.insert(crate::fs::file::FileObject::new(
            record, access, granted, share,
        ))?;
        self.file(id).expect("just made").init();
        Some(id)
    }

    /// A window station named `name` with `flags`; none when the pool is exhausted. Its creator's
    /// reference is the caller's: the boot's WinSta0 keeps it, so the window station is permanent.
    pub fn create_window_station(&mut self, name: &'static str, flags: u32) -> Option<ObjectId> {
        self.insert(WindowStationObject { name, flags })
    }

    /// A desktop named `name` with `flags`; none when the pool is exhausted. Its creator's
    /// reference is the caller's, as a window station's.
    pub fn create_desktop(&mut self, name: &'static str, flags: u32) -> Option<ObjectId> {
        self.insert(DesktopObject { name, flags })
    }

    /// A key object naming `body`'s key.
    pub fn create_key(&mut self, body: crate::cm::KeyBody) -> Option<ObjectId> {
        self.insert(body)
    }

    // --- Typed access ------------------------------------------------------------------------

    /// The body index of the live dispatcher object `id`, when it is of `kind`.
    fn body_index(&mut self, id: ObjectId, kind: ObjectType) -> Option<u16> {
        let index = id.body_of(kind)?;
        self.is_live(id).then_some(index)
    }

    // The dispatcher objects: the body's name in the dispatcher database, for a live object of
    // the kind (the body itself is reached there, with the dispatch token).

    /// The event object's body: its waitable name.
    #[cfg(test)]
    pub fn event(&mut self, id: ObjectId) -> Option<WaitableId> {
        self.body_index(id, ObjectType::Event)
            .map(WaitableId::Event)
    }

    /// The semaphore object's body: its waitable name.
    #[cfg(test)]
    pub fn semaphore(&mut self, id: ObjectId) -> Option<WaitableId> {
        self.body_index(id, ObjectType::Semaphore)
            .map(WaitableId::Semaphore)
    }

    /// The mutex object's body.
    pub fn mutex(&mut self, id: ObjectId) -> Option<MutexId> {
        self.body_index(id, ObjectType::Mutex).map(MutexId)
    }

    /// The waitable timer object's body.
    #[cfg(test)]
    pub fn timer(&mut self, id: ObjectId) -> Option<TimerId> {
        self.body_index(id, ObjectType::Timer)
            .map(TimerId::Waitable)
    }

    /// The thread object's record.
    pub fn thread(&mut self, id: ObjectId) -> Option<ThreadId> {
        self.body_index(id, ObjectType::Thread).map(ThreadId)
    }

    /// The process object's body: its index in the dispatcher's process-object pool.
    pub fn process(&mut self, id: ObjectId) -> Option<u16> {
        self.body_index(id, ObjectType::Process)
    }

    /// The ordinal the next created thread of the process `process` names takes (see
    /// [`crate::process::ordinals::Ordinals::free`]): its lowest one never taken, or held by a
    /// thread whose object is gone. None when every ordinal is held by a thread something still
    /// references, or `process` names no live process.
    pub fn free_ordinal(&mut self, process: ObjectId) -> Option<u16> {
        let index = self.body_index(process, ObjectType::Process)?;
        let threads = &self.threads.headers;
        self.processes.records[index as usize].free(|thread| {
            thread.kind == ObjectType::Thread
                && threads
                    .get(thread.index as usize)
                    .is_some_and(|header| header.names(thread.generation))
        })
    }

    /// The live process object at process pool `index`, if any.
    pub fn processes_live(&mut self, index: u16) -> Option<ObjectId> {
        let id = self.id(ObjectType::Process, index);
        self.is_live(id).then_some(id)
    }

    /// The process `id` names has ended with `exit_status`: its object signals, once, and its
    /// waiters wake (no boost: the end grants none).
    #[cfg(test)]
    pub fn signal_process_end(&mut self, id: ObjectId, exit_status: u32) {
        if let Some(index) = self.body_index(id, ObjectType::Process) {
            signal_process_body(index, exit_status);
        }
    }

    /// The waitable name of a live waitable object (see [`ObjectId::waitable`]); none for an
    /// object no wait can name, or a dead id.
    #[cfg(test)]
    pub fn waitable(&mut self, id: ObjectId) -> Option<WaitableId> {
        if !self.is_live(id) {
            return None;
        }
        id.waitable()
    }

    /// The thread object whose record is `thread`; none for the idle thread's record (no object
    /// names it) or one holding no live object.
    pub fn thread_object(&mut self, thread: ThreadId) -> Option<ObjectId> {
        if thread.index() as usize >= THREADS {
            return None;
        }
        let id = self.id(ObjectType::Thread, thread.index());
        self.is_live(id).then_some(id)
    }

    /// The thread object whose client id is `thread_id`, among the threads that have not ended of
    /// the process whose scheduling record is `owner`; none when no such thread has it (a thread of
    /// another process is not the owner's).
    pub fn thread_by_client_id(
        &mut self,
        owner: *const crate::sched::process::SchedProcess,
        thread_id: u32,
    ) -> Option<ObjectId> {
        with_bodies(|bodies| {
            (0..THREADS as u16).find_map(|index| {
                let id = self.id(ObjectType::Thread, index);
                let thread = bodies.thread(self.thread(id)?);
                let found = core::ptr::eq(thread.process, owner)
                    && thread.thread_id() == thread_id
                    && thread.state() != crate::sched::thread::ThreadState::Terminated;
                found.then_some(id)
            })
        })
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
    pub fn dereference(&mut self, id: ObjectId) -> Option<Followup> {
        let header = self.header(id)?;
        debug_assert!(
            header.pointers > header.handles,
            "a reference beyond the handles' is held"
        );
        header.pointers -= 1;
        if header.pointers == 0 {
            return self.delete(id);
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
    /// Returns what the caller must finish, in order.
    pub fn handle_closed(&mut self, id: ObjectId) -> Followups {
        let mut followups = Followups::none();
        let Some(header) = self.header(id) else {
            return followups;
        };
        debug_assert!(header.handles > 0, "a handle closes once");
        header.handles -= 1;
        if header.handles == 0 {
            self.forget_name(id);
            if let Some(file) = self.file(id) {
                followups.push(Some(Followup::FileCleanup {
                    record: file.record,
                    access: file.access,
                    share: file.share,
                    delete_on_close: file.delete_on_close,
                }));
            }
        }
        followups.push(self.dereference(id));
        followups
    }

    /// Delete the object `id` names: its kind's teardown, then the record is dead and its id stale.
    /// A section leaves its frames (and a file's section its file object; an image section its
    /// segment's, when it held the segment's last reference) to the caller, a file
    /// object its record's reference; an owned mutex leaves its owner's list; no other
    /// kind here needs more than the record going: a waitable's last reference is gone, so nothing
    /// waits on it; a thread's record stays as it ended (its pages are released when the record is
    /// reused); a process's record is free for the next process once its object is gone.
    fn delete(&mut self, id: ObjectId) -> Option<Followup> {
        let followup = match id.kind {
            ObjectType::Timer => {
                // Nothing may expire or queue an APC for a timer no one can reach.
                with_bodies(|bodies| bodies.cancel_timer(TimerId::Waitable(id.index)));
                None
            }
            ObjectType::Mutex => {
                // An owned mutex leaves its owner's list (the owner's end has nothing to abandon).
                with_bodies(|bodies| bodies.forget_mutex(MutexId(id.index)));
                None
            }
            ObjectType::Section => {
                let section = core::mem::replace(
                    self.section(id).expect("deleting a live section"),
                    SectionObject::none(),
                );
                match section.segment {
                    // An image section's frames and file are its segment's.
                    Some(segment) => self.dereference_segment(segment),
                    None => Some(Followup::Section {
                        frames: section.frames,
                        file_object: section.file_object,
                    }),
                }
            }
            ObjectType::File => Some(Followup::FileClose {
                record: self.file(id).expect("deleting a live file object").record,
            }),
            ObjectType::Event
            | ObjectType::Semaphore
            | ObjectType::Thread
            | ObjectType::Process
            | ObjectType::Directory
            | ObjectType::WindowStation
            | ObjectType::Desktop
            | ObjectType::Key => None,
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

    /// The wait thread record `thread` is about to enter holds `objects`, dispatcher objects all,
    /// for its whole life: a reference on each, released by [`Directory::release_wait`] when the
    /// wait returns — or when the thread ends without returning. False, and nothing held, when one
    /// of them is gone already (a handle another thread closed meanwhile).
    pub fn hold_wait(&mut self, thread: u16, objects: &[ObjectId]) -> bool {
        debug_assert!(self.waits[thread as usize]
            .objects
            .iter()
            .all(Option::is_none));
        debug_assert!(
            objects.iter().all(|id| id.waitable().is_some()),
            "a wait holds dispatcher objects"
        );
        if !objects.iter().all(|&id| self.is_live(id)) {
            return false;
        }
        for (slot, &id) in self.waits[thread as usize].objects.iter_mut().zip(objects) {
            *slot = Some(id);
        }
        for &id in objects {
            self.reference(id);
        }
        true
    }

    /// Release the references thread record `thread`'s wait holds. The objects that go with them
    /// are dispatcher objects, whose deletion leaves nothing to finish.
    pub fn release_wait(&mut self, thread: u16) {
        let held = core::mem::replace(&mut self.waits[thread as usize], WaitReferences::none());
        for id in held.objects.iter().flatten() {
            let left = self.dereference(*id);
            assert!(
                left.is_none(),
                "a dispatcher object's deletion leaves nothing"
            );
        }
    }

    /// A thread has ended, or is ending on its way out: its wait's references, if it ended inside
    /// one, and the thread's own reference on its object go. Its record is free once nothing else
    /// holds it. The exit calls this in the directory hold it retires the thread in: a retired
    /// thread waits for nothing, a lock included.
    pub fn end_thread_references(&mut self, thread: ThreadId) {
        if let Some(id) = self.thread_object(thread) {
            self.release_wait(id.index);
            let left = self.dereference(id);
            debug_assert!(left.is_none(), "a thread object's deletion leaves nothing");
        }
    }

    // --- Rundown -----------------------------------------------------------------------------

    /// Cancel every live timer whose completion APC targets `thread` (it is ending: nothing may
    /// queue to it any more).
    pub fn run_down_timers(&mut self, thread: ThreadId) {
        with_bodies(|bodies| {
            for index in 0..TIMERS as u16 {
                if self.timers.is_live_at(index)
                    && bodies.waitable_timer_mut(index).apc_thread() == Some(thread)
                {
                    bodies.cancel_timer(TimerId::Waitable(index));
                }
            }
        });
    }

    /// The process whose scheduling record is `owner` is gone: the records its threads left start
    /// over (their pages went with its address space). Nothing else here is the process's alone:
    /// its handles are closed and its threads have ended by now, so every object only it held went
    /// with its last reference, and one still live is another process's too — or a leak, which
    /// only the sweep at quiescence can tell ([`Directory::sweep_next`]). A thread record whose
    /// object still lives (another process holds a handle to the thread) stays as it ended: its
    /// object is still waitable and its exit code still readable.
    pub fn process_ended(&mut self, owner: *const crate::sched::process::SchedProcess) {
        with_bodies(|bodies| {
            for index in 0..THREADS as u16 {
                let thread = ThreadId(index);
                let left = !self.threads.is_live_at(index)
                    && core::ptr::eq(bodies.thread(thread).process, owner);
                if left {
                    bodies.renew_thread(thread);
                }
            }
        });
    }

    /// One step of the sweep at quiescence, once no process remains that has not been torn down:
    /// every reference a process held went with its end, so every object (and image segment) still
    /// live is a leak. The step deletes the next one, an object first, then a segment no object
    /// took with it; none once nothing is left. Each step is one leak. Process objects are not
    /// swept (the reaped process's own goes with its own reference, at its teardown's end), nor the
    /// permanent directory, window station and desktop, which outlive every process. The caller
    /// finishes what a step leaves (a leaked section's or segment's hold on its frames) between
    /// steps, then ends the sweep ([`Directory::sweep_end`]).
    pub fn sweep_next(&mut self) -> Option<Leak> {
        for kind in [
            ObjectType::Event,
            ObjectType::Semaphore,
            ObjectType::Mutex,
            ObjectType::Timer,
            ObjectType::Thread,
            ObjectType::Section,
            ObjectType::File,
            ObjectType::Key,
        ] {
            let live = self.headers(kind).iter().position(|header| header.live);
            if let Some(index) = live {
                let id = self.id(kind, index as u16);
                return Some(Leak {
                    followup: self.delete(id),
                });
            }
        }
        // The image sections went above, and every view with its process: a segment left is a
        // leak too.
        let index = self
            .segments
            .headers
            .iter()
            .position(|header| header.live)?;
        Some(Leak {
            followup: Some(self.delete_segment(index as u16)),
        })
    }

    /// The sweep's end: every thread record starts over, and every wait's references and every
    /// name are freed.
    pub fn sweep_end(&mut self) {
        with_bodies(|bodies| {
            for (index, waits) in self.waits.iter_mut().enumerate() {
                bodies.renew_thread(ThreadId(index as u16));
                *waits = WaitReferences::none();
            }
        });
        for entry in self.names.iter_mut() {
            *entry = NameEntry::free();
        }
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

/// Signal the process object whose body is at `index` with `exit_status`, once, waking its waiters
/// (no boost: the end grants none).
fn signal_process_body(index: u16, exit_status: u32) {
    with_bodies(|bodies| {
        let process = bodies.process_object_mut(index);
        process.exit_status = exit_status;
        process.waitable.signal_state = 1;
        if process.waitable.has_waiters() {
            let waitable = process.waitable.id();
            bodies.satisfy_waiters(waitable, 0);
        }
    });
}

#[cfg(target_arch = "x86")]
pub use target::*;

/// The kernel's directory and the services' side of it: the lock, the references a service holds,
/// the follow-ups finished after the lock, and the current process's handles.
#[cfg(target_arch = "x86")]
mod target {
    use core::num::NonZeroU32;
    use core::ptr::NonNull;

    use super::*;
    use crate::interrupt::irql;
    use crate::level::{At, Passive};
    use crate::sync::{ShortGuard, ShortLock};

    /// The kernel's one directory, behind its short lock. Built in place at its first acquisition:
    /// by value it would pass through the stack, which is smaller than it.
    static DIRECTORY: ShortLock<Directory> =
        // SAFETY: `write_empty` writes a whole directory at the address it is handed, and takes no
        // lock.
        unsafe { ShortLock::in_place(Directory::write_empty) };

    /// The directory, locked for as long as the guard lives. The guard keeps the passive token
    /// borrowed, so nothing that takes it — a wait, a switch, a user-memory copy — runs while the
    /// directory is held.
    pub fn lock(passive: &mut At<Passive>) -> ShortGuard<'_, Directory> {
        DIRECTORY.lock(passive)
    }

    /// Run `f` on the locked directory: the bridge for code that holds no passive token, which it
    /// makes for the hold (see [`lock`]).
    ///
    /// # Panics
    ///
    /// The processor is above the passive level: inside the directory's lock already (`f`, or what
    /// it calls, taking it again), or at a raised level, where nothing may wait for it.
    pub fn locked<R>(f: impl FnOnce(&mut Directory) -> R) -> R {
        assert_eq!(
            crate::pcr::pcr().current(),
            irql::PASSIVE,
            "the directory's bridge entered above the passive level"
        );
        // SAFETY: a passive entry (see `At::enter`): the ledger reads the passive level, and the
        // token stays on this thread, dropped with this frame.
        let mut passive = unsafe { At::<Passive>::enter() };
        let mut directory = DIRECTORY.lock(&mut passive);
        f(&mut directory)
    }

    /// Whether no thread holds the directory, as the idle thread, which cannot wait for it, finds
    /// it.
    pub fn is_free() -> bool {
        DIRECTORY.is_free()
    }

    /// Finish what the directory left its caller when an object's last handle or last reference
    /// went (see the module notes): a section's hold on its frames (and a file's section's or a
    /// segment's on its file object), a file object's cleanup — which may delete the file, on disk
    /// — and its record's close. Runs outside the directory's lock, at the passive level.
    pub fn finish(followup: Followup) {
        match followup {
            Followup::Section {
                frames,
                file_object,
            } => {
                crate::nt::section::release_frames(frames);
                if let Some(file_object) = file_object {
                    unmap_file(file_object);
                }
            }
            Followup::FileCleanup {
                record,
                access,
                share,
                delete_on_close,
            } => crate::fs::io::cleanup(record, access, share, delete_on_close),
            Followup::FileClose { record } => crate::fs::io::close(record),
        }
    }

    /// A file-backed section, or an image segment, is gone: its file is mapped once less, and its
    /// reference on the file object goes (the object's close follows, when that was its last
    /// reference).
    fn unmap_file(file_object: ObjectId) {
        let Some(record) = locked(|directory| directory.file(file_object).map(|file| file.record))
        else {
            return;
        };
        crate::fs::file::with_records(|records| records.get_mut(record).user_mapped -= 1);
        release(file_object);
    }

    /// A reference on an object, held for as long as the value lives:
    /// dropping it releases the reference, and the last one deletes the object.
    pub struct ObRef {
        id: ObjectId,
    }

    impl ObRef {
        /// The referenced object's id.
        pub fn id(&self) -> ObjectId {
            self.id
        }

        // The dispatcher objects' bodies, by their names in the dispatcher database (the
        // reference's kind is the caller's to know): the reference keeps the body the object's.

        /// The referenced event's body.
        pub fn event(&self) -> WaitableId {
            WaitableId::Event(self.body(ObjectType::Event))
        }

        /// The referenced semaphore's body.
        pub fn semaphore(&self) -> WaitableId {
            WaitableId::Semaphore(self.body(ObjectType::Semaphore))
        }

        /// The referenced mutex's body.
        pub fn mutex(&self) -> MutexId {
            MutexId(self.body(ObjectType::Mutex))
        }

        /// The referenced waitable timer's body.
        pub fn timer(&self) -> TimerId {
            TimerId::Waitable(self.body(ObjectType::Timer))
        }

        /// The referenced thread's record.
        pub fn thread(&self) -> ThreadId {
            ThreadId(self.body(ObjectType::Thread))
        }

        /// The referenced process object's body: its index in the dispatcher's process-object
        /// pool.
        pub fn process(&self) -> u16 {
            self.body(ObjectType::Process)
        }

        /// The referenced section's body, as it is now.
        pub fn section(&self) -> SectionObject {
            locked(|directory| {
                *directory
                    .section(self.id)
                    .expect("a referenced section lives")
            })
        }

        /// The referenced object's body index, as an object of `kind`.
        fn body(&self, kind: ObjectType) -> u16 {
            self.id
                .body_of(kind)
                .expect("a reference of the kind asked")
        }
    }

    impl Drop for ObRef {
        fn drop(&mut self) {
            release(self.id);
        }
    }

    /// A referenced file object: the reference lives as long as the value, which reads as the
    /// object itself.
    ///
    /// The object is reached outside the directory's lock, as Windows 2000 reaches a file object
    /// outside the object manager's: what its open set (its record, its access and rights, its
    /// sharing, its options) is never written again while it lives, and reads freely; its position
    /// and its directory search change only under the object's own lock, through
    /// [`crate::fs::io::serialized`], the one way to the object mutably.
    pub struct Referenced<T: 'static> {
        _reference: ObRef,
        record: NonNull<T>,
    }

    impl<T: 'static> Referenced<T> {
        /// The record itself, borrowed by nothing: how a caller reaches a part of it (a lock)
        /// without borrowing the whole while another thread may hold it.
        pub fn as_ptr(&self) -> *mut T {
            self.record.as_ptr()
        }
    }

    impl<T: 'static> core::ops::Deref for Referenced<T> {
        type Target = T;

        fn deref(&self) -> &T {
            // SAFETY: the record is a pool record of the directory, at its final address for the
            // kernel's life, and its object is held for the value's life. The fields read through
            // this are the ones its open set, which nothing writes while the object lives (see
            // the type's notes).
            unsafe { self.record.as_ref() }
        }
    }

    /// The file object `reference` holds, referenced for as long as the value lives (see
    /// [`Referenced`]).
    pub fn file_object(reference: ObRef) -> Referenced<crate::fs::file::FileObject> {
        let record = locked(|directory| directory.file(reference.id()).map(NonNull::from))
            .expect("a referenced file object lives");
        Referenced {
            _reference: reference,
            record,
        }
    }

    /// Take a reference on `id` for the caller's scope; none when it names nothing.
    pub fn reference(id: ObjectId) -> Option<ObRef> {
        locked(|directory| directory.reference(id)).then(|| ObRef { id })
    }

    /// The object the current process's `handle` names, referenced, when it is of `kind` (any
    /// kind for none). None for a handle naming nothing, another kind of object, or a record that
    /// is not an object (Windows reports them alike, an invalid handle).
    pub fn reference_by_handle(handle: u32, kind: Option<ObjectType>) -> Option<ObRef> {
        let id = crate::process::current()
            .lookup_handle(handle)
            .and_then(|entry| entry.object_id())
            .filter(|id| kind.is_none_or(|kind| id.kind == kind))?;
        reference(id)
    }

    /// The live object `name` binds, referenced (the look-up and the reference in one hold of the
    /// directory, so the object cannot go between them); none when it binds none.
    pub fn reference_by_name(name: &[u8]) -> Option<ObRef> {
        locked(|directory| {
            let id = directory.lookup_name(name)?;
            directory.reference(id).then(|| ObRef { id })
        })
    }

    /// Drop a reference on `id` (the last one deletes the object, the caller finishing what the
    /// deletion leaves once the directory is released).
    pub fn release(id: ObjectId) {
        if let Some(followup) = locked(|directory| directory.dereference(id)) {
            finish(followup);
        }
    }

    /// A view went: drop its reference on what it mapped (the last one deletes it, the caller
    /// finishing what the deletion leaves).
    pub fn release_mapping(mapping: Mapping) {
        if let Some(followup) = locked(|directory| directory.release_mapping(mapping)) {
            finish(followup);
        }
    }

    /// Publish a new object: a handle to it in `process` (the current one) with `access` and
    /// `inheritance`, and its creator's reference dropped — the handle holds it from now on. A
    /// failure (the table is full) takes the object back with it.
    pub fn publish(
        process: &crate::process::Process,
        id: ObjectId,
        access: u32,
        inherit: bool,
    ) -> Option<NonZeroU32> {
        let handle = process.insert_object(id, access, inherit);
        release(id);
        handle
    }

    /// Open the object `id` names as a new handle in `process`; none when the table is full or
    /// the object is gone.
    pub fn open(
        process: &crate::process::Process,
        id: ObjectId,
        access: u32,
        inherit: bool,
    ) -> Option<NonZeroU32> {
        process.insert_object(id, access, inherit)
    }

    /// The process `id` names has ended with `exit_status`: its object signals, once, and its
    /// waiters wake. The process's own reference keeps the object, so the directory is not
    /// reached: the last thread's exit signals it after the thread has retired, when it must not
    /// be preempted.
    pub fn signal_process_end(id: ObjectId, exit_status: u32) {
        let index = id.body_of(ObjectType::Process).expect("a process's object");
        signal_process_body(index, exit_status);
    }

    /// The thread object of the running thread, if it is a pooled thread (every thread that runs
    /// a service is).
    pub fn current_thread() -> Option<ObjectId> {
        let thread = crate::sched::try_current_thread()?;
        locked(|directory| directory.thread_object(thread))
    }

    /// Wait on `objects`, dispatcher objects all, for the running thread: each is referenced for
    /// the wait's whole life — replays after an APC included — and released when `wait` returns.
    /// A thread that ends inside the wait releases them on its way out
    /// ([`Directory::end_thread_references`]). None, with nothing waited on, when one of the
    /// objects is gone already (a handle another thread closed meanwhile).
    pub fn waiting<R>(objects: &[ObjectId], wait: impl FnOnce() -> R) -> Option<R> {
        let index = current_thread()
            .expect("a service runs on a pooled thread")
            .index;
        if !locked(|directory| directory.hold_wait(index, objects)) {
            return None;
        }
        let result = wait();
        locked(|directory| directory.release_wait(index));
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    //! The object manager's pure core: counts, generations, names, the waits' references, and the
    //! kinds' teardowns, over a directory of the tests' own.

    use super::*;
    use crate::sched::testkit::record;
    use crate::sched::thread::Thread;

    // The rig: leaked records at their final addresses, as the scheduler's test modules build them.
    // A directory comes with a fresh dispatcher of its own, which holds its dispatcher objects'
    // bodies.

    fn directory() -> &'static mut Directory {
        crate::sched::testkit::dispatcher();
        let mut directory = Box::<Directory>::new_uninit();
        // SAFETY: the box is valid, aligned and the records' final address once leaked.
        unsafe { Directory::write_empty(directory.as_mut_ptr()) };
        // SAFETY: written whole just above.
        Box::leak(unsafe { directory.assume_init() })
    }

    /// The dispatcher of the newest directory.
    fn dispatcher() -> &'static mut Dispatcher {
        crate::sched::testkit::installed()
    }

    fn thread() -> crate::sched::testkit::Rec<Thread> {
        let process = Box::leak(Box::new(crate::sched::process::SchedProcess::new(
            0x0090_0000,
            8,
        )));
        crate::sched::testkit::thread(process)
    }

    /// Close a handle to `id`, collecting what the caller must finish.
    fn closed(directory: &mut Directory, id: ObjectId) -> Vec<Followup> {
        directory.handle_closed(id).iter().collect()
    }

    /// The sweep at quiescence, step by step as the reap runs it: how many leaks it took, and
    /// what their deletions left.
    fn sweep(directory: &mut Directory) -> (usize, Vec<Followup>) {
        let mut leaks = 0;
        let mut left = Vec::new();
        while let Some(leak) = directory.sweep_next() {
            leaks += 1;
            left.extend(leak.followup);
        }
        directory.sweep_end();
        (leaks, left)
    }

    /// A published object, as a create leaves it: one handle, the creator's reference dropped.
    fn published(directory: &mut Directory, id: ObjectId) {
        assert!(directory.handle_opened(id));
        assert_eq!(directory.dereference(id), None);
    }

    /// An object lives as long as anything references it: its creator's reference and each handle's
    /// count, the last reference deletes it, and its id goes stale with it.
    #[test]
    fn an_object_lives_while_referenced() {
        let directory = directory();
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
        assert_eq!(directory.dereference(id), None);
        assert_eq!(directory.counts(id), Some((1, 1)), "the handle holds it");
        assert!(directory.reference(id));
        assert_eq!(closed(directory, id), vec![]);
        assert!(
            directory.is_live(id),
            "a reference outlives the last handle"
        );
        assert_eq!(directory.dereference(id), None);
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
        let first = directory.create_semaphore(0, 1).unwrap();
        assert_eq!(directory.dereference(first), None);
        let second = directory.create_semaphore(3, 5).unwrap();
        assert_eq!(first.index, second.index, "the record is reused");
        assert_ne!(first.generation, second.generation);
        assert!(directory.semaphore(first).is_none());
        let body = directory.semaphore(second).unwrap();
        assert_eq!(dispatcher().waitable(body).signal_state(), 3);
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
        let id = directory.create_semaphore(0, 1).unwrap();
        published(directory, id);
        directory.bind_name(b"F2K.sync.semaphore", id).unwrap();
        assert_eq!(directory.lookup_name(b"F2K.sync.semaphore"), Some(id));
        assert_eq!(
            directory.lookup_name(b"f2k.sync.semaphore"),
            None,
            "case-sensitive"
        );
        assert_eq!(directory.lookup_name(b"F2K.sync"), None);
        assert!(directory.reference(id));
        assert_eq!(closed(directory, id), vec![]);
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
        let waiter = directory.create_thread_in(1..THREADS).unwrap();
        let event = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        published(directory, event);

        assert!(directory.hold_wait(waiter.index, &[event]));
        assert_eq!(directory.counts(event), Some((2, 1)));
        assert_eq!(
            closed(directory, event),
            vec![],
            "the program closes its handle"
        );
        assert!(directory.is_live(event), "the wait holds it");
        assert!(
            directory.waitable(event).is_some(),
            "still waitable for its waiter"
        );

        directory.release_wait(waiter.index);
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
        published(directory, timer);
        let record = directory.timer(timer).unwrap();
        dispatcher.set_waitable_timer(record, 1_000_000, 0, 0, false, 0);
        assert!(dispatcher.timer(record).inserted());

        assert!(directory.hold_wait(waiter.index, &[timer]));
        assert_eq!(directory.counts(timer), Some((2, 1)));
        assert_eq!(
            closed(directory, timer),
            vec![],
            "the program closes its handle"
        );
        assert!(directory.is_live(timer), "the wait holds it");
        assert!(
            dispatcher.timer(record).inserted(),
            "still armed for its waiter"
        );

        directory.release_wait(waiter.index);
        assert!(
            !directory.is_live(timer),
            "the wait's return released the last reference"
        );
        assert!(
            !dispatcher.waitable_timer_mut(timer.index).armed(),
            "deletion cancelled it"
        );
    }

    /// A timer the sweep at quiescence deletes (a leaked reference) leaves the timer table with it.
    #[test]
    fn the_sweep_disarms_a_leaked_timer() {
        let directory = directory();
        let dispatcher = dispatcher();
        let leaked = directory.create_timer(true).unwrap();
        dispatcher.set_waitable_timer(directory.timer(leaked).unwrap(), 1_000_000, 0, 0, false, 0);
        assert_eq!(sweep(directory).0, 1);
        assert!(
            !dispatcher.waitable_timer_mut(leaked.index).armed(),
            "the leaked timer left the table"
        );
    }

    /// A wait's references keep its objects from being recycled while the waiter is away (a
    /// suspend unwinds the wait, which replays later): the record cannot go to a new object.
    #[test]
    fn a_waits_references_keep_records_from_reuse() {
        let directory = directory();
        let waiter = directory.create_thread_in(1..THREADS).unwrap();
        let semaphore = directory.create_semaphore(0, 1).unwrap();
        published(directory, semaphore);
        assert!(directory.hold_wait(waiter.index, &[semaphore]));
        assert_eq!(closed(directory, semaphore), vec![]);
        let fresh = directory.create_semaphore(1, 1).unwrap();
        assert_ne!(
            fresh.index, semaphore.index,
            "the held record is not handed out"
        );
        assert!(
            directory.semaphore(semaphore).is_some(),
            "the waiter's object is still its own"
        );
        directory.release_wait(waiter.index);
        assert!(!directory.is_live(semaphore));
    }

    /// A wait over several objects holds each, the same object twice twice.
    #[test]
    fn a_wait_holds_every_object_it_names() {
        let directory = directory();
        let waiter = directory.create_thread_in(1..THREADS).unwrap();
        let a = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let b = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        assert!(directory.hold_wait(waiter.index, &[a, b, a]));
        assert_eq!(directory.counts(a), Some((3, 0)));
        assert_eq!(directory.counts(b), Some((2, 0)));
        directory.release_wait(waiter.index);
        assert_eq!(
            directory.counts(a),
            Some((1, 0)),
            "back to the creators' references"
        );
        assert_eq!(directory.counts(b), Some((1, 0)));
    }

    /// A wait refuses an object gone before it could hold it (another thread closed its last
    /// handle): it holds nothing then, of that object or the others.
    #[test]
    fn a_wait_refuses_a_gone_object() {
        let directory = directory();
        let waiter = directory.create_thread_in(1..THREADS).unwrap();
        let live = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let gone = directory.create_semaphore(0, 1).unwrap();
        assert_eq!(directory.dereference(gone), None);
        assert!(!directory.hold_wait(waiter.index, &[live, gone]));
        assert_eq!(directory.counts(live), Some((1, 0)), "nothing held");
        assert!(
            directory.hold_wait(waiter.index, &[live]),
            "the slot is free"
        );
        directory.release_wait(waiter.index);
    }

    /// Ids name their dispatcher bodies by their own index, whatever their liveness; the kinds
    /// whose bodies the directory holds name none.
    #[test]
    fn ids_name_their_dispatcher_bodies() {
        let id = |kind| ObjectId {
            kind,
            index: 5,
            generation: 2,
        };
        assert_eq!(id(ObjectType::Event).waitable(), Some(WaitableId::Event(5)));
        assert_eq!(
            id(ObjectType::Thread).waitable(),
            Some(WaitableId::Thread(ThreadId(5)))
        );
        assert_eq!(
            id(ObjectType::Process).waitable(),
            Some(WaitableId::Process(5))
        );
        for kind in [ObjectType::Section, ObjectType::File, ObjectType::Key] {
            assert_eq!(id(kind).waitable(), None);
        }
    }

    /// A handle's close leaves at most a file object's cleanup and its close, in that order; an
    /// object of another kind its deletion's follow-up alone.
    #[test]
    fn a_close_leaves_its_followups_in_order() {
        let directory = directory();
        let event = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        published(directory, event);
        assert_eq!(directory.handle_closed(event), Followups::none());
        let data = directory.create_section(SectionObject::none()).unwrap();
        published(directory, data);
        let left: Vec<_> = directory.handle_closed(data).iter().collect();
        assert_eq!(left.len(), 1, "the section's frames");
    }

    /// Thread records: created threads never take the main thread's record, the pool exhausts at
    /// its capacity, and a record's pointer resolves to its object.
    #[test]
    fn thread_records_and_their_ranges() {
        let directory = directory();
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
        let record = ThreadId(last.index);
        assert_eq!(directory.thread_object(record), Some(last));
        assert_eq!(
            directory.thread_object(crate::sched::database::IDLE_THREAD),
            None,
            "the idle thread's record names no object"
        );
        // A thread's own reference released: its record is free again.
        assert_eq!(directory.dereference(last), None);
        assert_eq!(directory.thread_object(record), None);
        assert_eq!(
            directory.create_thread_in(1..THREADS).map(|id| id.index),
            Some(last.index)
        );
    }

    /// Two processes' threads interleave in the pool, any process's thread taking the lowest free
    /// record; a client-id lookup finds only the asking process's own threads.
    #[test]
    fn thread_lookups_by_client_id_stay_within_their_process() {
        use crate::sched::process::SchedProcess;
        let directory = directory();
        let a = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8))) as *mut SchedProcess;
        let b = Box::leak(Box::new(SchedProcess::new(0x00A0_0000, 8))) as *mut SchedProcess;
        // A's main thread, B's main thread, then a created thread of A's: records 0, 1, 2.
        let threads = [(a, 8), (b, 16), (a, 20)].map(|(owner, client_id)| {
            let id = directory.create_thread().unwrap();
            let record = dispatcher().thread_mut(directory.renew_thread(id));
            record.process = owner;
            record.thread_id = client_id;
            id
        });
        assert_eq!(threads.map(|id| id.index), [0, 1, 2]);
        assert_eq!(directory.thread_by_client_id(a, 20), Some(threads[2]));
        assert_eq!(directory.thread_by_client_id(a, 8), Some(threads[0]));
        assert_eq!(directory.thread_by_client_id(b, 16), Some(threads[1]));
        assert_eq!(directory.thread_by_client_id(b, 20), None, "A's thread");
        assert_eq!(directory.thread_by_client_id(a, 16), None, "B's thread");
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
        dispatcher.acquire_mutex(directory.mutex(id).unwrap(), owner.id());
        assert!(!owner.owned_mutexes.is_empty());
        assert!(directory.waitable(id).is_some(), "a mutex is waitable");
        assert_eq!(directory.dereference(id), None);
        assert!(owner.owned_mutexes.is_empty(), "the deletion unlinked it");
        dispatcher.abandon_mutexes(owner.id());
    }

    /// `\BaseNamedObjects` is made once, at its first need, and is permanent: no sweep
    /// deletes it, nor counts it as a leak; no wait can name it.
    #[test]
    fn the_named_objects_directory_is_permanent() {
        let directory = directory();
        let id = directory.named_objects().unwrap();
        assert_eq!(directory.named_objects(), Some(id), "one directory");
        assert_eq!(directory.waitable(id), None);
        // An open's handle, then its close: the creator's reference stays.
        assert!(directory.handle_opened(id));
        assert_eq!(closed(directory, id), vec![]);
        assert_eq!(directory.counts(id), Some((1, 0)));
        assert_eq!(sweep(directory).0, 0);
        assert!(directory.is_live(id), "it outlives every process");
        assert_eq!(directory.named_objects(), Some(id));
    }

    /// A window station and its desktop, as the boot makes WinSta0 and Default: typed, never
    /// waited on, and permanent through their creator's reference: a process's handles come and
    /// go, and no sweep deletes them or counts them as leaks.
    #[test]
    fn window_stations_and_desktops_are_permanent() {
        let directory = directory();
        let station = directory.create_window_station("WinSta0", 1).unwrap();
        let desktop = directory.create_desktop("Default", 0).unwrap();
        assert_eq!(directory.window_station(station).unwrap().name, "WinSta0");
        assert_eq!(directory.window_station(station).unwrap().flags, 1);
        let record = directory.desktop(desktop).unwrap();
        assert_eq!((record.name, record.flags), ("Default", 0));
        assert!(directory.window_station(desktop).is_none(), "typed");
        assert!(directory.desktop(station).is_none(), "typed");
        assert_eq!(directory.waitable(station), None);
        assert_eq!(directory.waitable(desktop), None);
        assert_eq!(directory.create_window_station("Other", 0), None, "one");
        for id in [station, desktop] {
            assert!(directory.handle_opened(id));
            assert_eq!(closed(directory, id), vec![]);
            assert_eq!(directory.counts(id), Some((1, 0)));
        }
        assert_eq!(sweep(directory).0, 0);
        assert!(directory.is_live(station) && directory.is_live(desktop));
    }

    /// The sweep at quiescence deletes whatever outlived its process (a reference leak, reported)
    /// and starts every thread record and name over.
    #[test]
    fn the_sweep_clears_the_directory() {
        let directory = directory();
        let leaked = directory
            .create_event(EventKind::Notification, true)
            .unwrap();
        directory.bind_name(b"left", leaked).unwrap();
        let main = directory.create_thread_in(0..1).unwrap();
        record(ThreadId(main.index)).teb_va = 0x7FFD_E000;
        assert_eq!(sweep(directory).0, 2);
        assert_eq!(directory.live_objects(), 0);
        assert!(!directory.is_live(leaked));
        assert_eq!(directory.lookup_name(b"left"), None);
        assert_eq!(
            record(ThreadId(main.index)).teb_va(),
            0,
            "records start over"
        );
    }

    /// A process for the two-process tests: its scheduling record at its final address.
    fn sched_process(dir: u32) -> &'static mut crate::sched::process::SchedProcess {
        let process = Box::leak(Box::new(crate::sched::process::SchedProcess::new(dir, 8)));
        process
    }

    /// A thread of `process` on a pooled record in `range`, with its TEB at `teb`.
    fn pooled_thread(
        directory: &mut Directory,
        range: core::ops::Range<usize>,
        process: &mut crate::sched::process::SchedProcess,
        teb: u32,
    ) -> ObjectId {
        let id = directory.create_thread_in(range).unwrap();
        let thread = directory.renew_thread(id);
        dispatcher().thread_mut(thread).teb_va = teb;
        // SAFETY: the process is leaked at its final address.
        unsafe { dispatcher().attach(ThreadId(id.index), process) };
        id
    }

    /// Two processes' objects share the pools: the first one's end — its handles closed, its
    /// threads' own references gone, then its records reset — takes only what it alone held. The
    /// other's objects, its name and its running thread stay whole, an object both held included;
    /// once the second ends too, nothing is left for the sweep.
    #[test]
    fn a_process_end_takes_only_its_own() {
        let directory = directory();
        let (a, b) = (sched_process(0x0090_0000), sched_process(0x00A0_0000));
        let a_main = pooled_thread(directory, 0..1, a, 0x7FFD_E000);
        let a_child = pooled_thread(directory, 1..THREADS, a, 0x7FFD_D000);
        let b_thread = pooled_thread(directory, 1..THREADS, b, 0x7FFD_C000);
        let a_event = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        published(directory, a_event);
        directory.bind_name(b"F2K.a", a_event).unwrap();
        let b_semaphore = directory.create_semaphore(0, 1).unwrap();
        published(directory, b_semaphore);
        directory.bind_name(b"F2K.b", b_semaphore).unwrap();
        // The first process opens the second's semaphore by its name.
        assert!(directory.handle_opened(b_semaphore));

        // The first process ends.
        for id in [a_event, b_semaphore] {
            assert_eq!(closed(directory, id), vec![]);
        }
        for id in [a_main, a_child] {
            assert_eq!(directory.dereference(id), None);
        }
        directory.process_ended(a);
        assert!(!directory.is_live(a_event), "its own went with its handle");
        assert_eq!(directory.lookup_name(b"F2K.a"), None);
        for id in [a_main, a_child] {
            let ended = record(ThreadId(id.index));
            assert!(ended.process.is_null() && ended.teb_va() == 0, "reset");
        }
        assert_eq!(directory.counts(b_semaphore), Some((1, 1)), "the other's");
        assert_eq!(directory.lookup_name(b"F2K.b"), Some(b_semaphore));
        assert!(directory.is_live(b_thread));
        let b_record = record(ThreadId(b_thread.index));
        assert!(core::ptr::eq(b_record.process, b) && b_record.teb_va() == 0x7FFD_C000);

        // The second ends: quiescence, and nothing leaked.
        assert_eq!(closed(directory, b_semaphore), vec![]);
        assert_eq!(directory.dereference(b_thread), None);
        directory.process_ended(b);
        assert_eq!(record(ThreadId(b_thread.index)).teb_va(), 0);
        assert_eq!(sweep(directory).0, 0);
        assert_eq!(directory.live_objects(), 0);
    }

    /// A process's end cannot tell a leaked reference from another process's: the object stays
    /// live, and so does a thread record whose object something still holds. The sweep at
    /// quiescence catches the leak, deletes it and reports it.
    #[test]
    fn the_sweep_at_quiescence_catches_a_leak() {
        let directory = directory();
        let (a, b) = (sched_process(0x0090_0000), sched_process(0x00A0_0000));
        let a_main = pooled_thread(directory, 0..1, a, 0x7FFD_E000);
        let b_thread = pooled_thread(directory, 1..THREADS, b, 0x7FFD_C000);
        let leaked = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        published(directory, leaked);
        // A reference the first process takes and never releases (a kernel bug), and one on its
        // own thread object.
        assert!(directory.reference(leaked));
        assert!(directory.reference(a_main));

        assert_eq!(closed(directory, leaked), vec![]);
        assert_eq!(directory.dereference(a_main), None);
        directory.process_ended(a);
        assert!(
            directory.is_live(leaked),
            "not the first process's end to judge"
        );
        assert!(directory.is_live(a_main));
        assert_eq!(
            record(ThreadId(a_main.index)).teb_va(),
            0x7FFD_E000,
            "a held thread's record stays as it ended"
        );

        assert_eq!(directory.dereference(b_thread), None);
        directory.process_ended(b);
        assert_eq!(sweep(directory).0, 2, "the event and the thread");
        assert_eq!(directory.live_objects(), 0);
        assert_eq!(record(ThreadId(a_main.index)).teb_va(), 0);
    }

    /// One namespace for every kind and both session prefixes: `Global\` and `Local\` name the same
    /// object as the bare name, and a name binds one object whatever kind asks.
    #[test]
    fn the_namespace_is_one_directory() {
        let directory = directory();
        let event = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        published(directory, event);
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
    /// exit code at the end; the sweep leaves it to its own reference, whose
    /// release frees the record for the next process; the pool's capacity is the process
    /// pool's.
    #[test]
    fn a_process_object_signals_its_end() {
        let directory = directory();
        let dispatcher = dispatcher();
        let id = directory.create_process().unwrap();
        assert_eq!(directory.processes_live(id.index), Some(id));
        assert_eq!(
            directory
                .process(id)
                .map(|body| dispatcher.process_object_mut(body).exit_status),
            Some(STILL_ACTIVE)
        );
        let waitable = directory.waitable(id).expect("a process is waitable");
        assert_eq!(dispatcher.waitable(waitable).signal_state(), 0);
        // A handle to it and the process's own reference.
        assert!(directory.handle_opened(id));
        assert_eq!(sweep(directory).0, 0, "a process object is no leak");
        assert!(directory.is_live(id));
        directory.signal_process_end(id, 3);
        assert_eq!(dispatcher.waitable(waitable).signal_state(), 1);
        assert_eq!(
            directory
                .process(id)
                .map(|body| dispatcher.process_object_mut(body).exit_status),
            Some(3)
        );
        assert_eq!(
            directory.dereference(id),
            None,
            "the process's own reference goes"
        );
        assert!(
            directory.is_live(id),
            "the handle still names the ended process"
        );
        assert_eq!(closed(directory, id), vec![]);
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
        published(directory, id);
        // A view's reference keeps it past its handle.
        assert!(directory.reference(id));
        assert_eq!(closed(directory, id), vec![]);
        assert_eq!(
            directory.dereference(id),
            Some(Followup::Section {
                frames: crate::mem::vm::SectionFrames::empty(),
                file_object: Some(file_object),
            })
        );
        assert_eq!(
            directory.sections.records[id.index as usize].size, 0,
            "the record holds no mapping any more"
        );
    }

    /// An image section of `segment`, as NtCreateSection makes one and publishes it (one handle).
    fn image_section(directory: &mut Directory, segment: SegmentId) -> ObjectId {
        let id = directory
            .create_section(SectionObject {
                size: 0x3000,
                image_base: 0x1000_0000,
                segment: Some(segment),
                ..SectionObject::none()
            })
            .unwrap();
        published(directory, id);
        id
    }

    /// An image file's segment is shared: every image section of the file and every view holds
    /// it, a view's section can be closed at once, and only the last of them hands its frames and
    /// its file object back — once. Its id goes stale with it.
    #[test]
    fn an_image_segment_lives_while_a_section_or_view_holds_it() {
        let directory = directory();
        let file_object = ObjectId {
            kind: ObjectType::File,
            index: 7,
            generation: 2,
        };
        let segment = directory
            .create_segment(ImageSegment {
                frames: crate::mem::vm::SectionFrames::empty(),
                file_object,
                image_base: 0x1000_0000,
                size: 0x3000,
            })
            .unwrap();
        // The first process's loader: its section made the segment (the creator's reference is
        // the section's), its view holds the segment, and its handle closes.
        let first = image_section(directory, segment);
        let view = Mapping::Image(segment);
        assert!(directory.reference_segment(segment), "the first view");
        assert_eq!(closed(directory, first), vec![]);
        assert!(
            !directory.is_live(first),
            "the view does not hold the section"
        );
        assert!(
            directory.segment(segment).is_some(),
            "the view holds the segment"
        );
        // A second process shares the segment.
        assert!(directory.reference_segment(segment), "the second section");
        let second = image_section(directory, segment);
        assert!(directory.reference_segment(segment), "the second view");
        assert_eq!(closed(directory, second), vec![]);
        assert_eq!(directory.release_mapping(view), None);
        assert_eq!(directory.segments.live(), 1, "one segment for the file");
        let gone = Followup::Section {
            frames: crate::mem::vm::SectionFrames::empty(),
            file_object: Some(file_object),
        };
        assert_eq!(directory.release_mapping(view), Some(gone));
        assert!(directory.segment(segment).is_none(), "its id is stale");
        assert!(!directory.reference_segment(segment));
        assert_eq!(directory.release_mapping(view), None);
        // A section that outlives the views is the last holder in its turn.
        let again = directory
            .create_segment(ImageSegment {
                frames: crate::mem::vm::SectionFrames::empty(),
                file_object,
                image_base: 0x1000_0000,
                size: 0x3000,
            })
            .unwrap();
        assert_eq!(again.index, segment.index, "the record is reused");
        assert_ne!(again, segment, "under a new generation");
        let section = image_section(directory, again);
        assert!(directory.reference_segment(again), "a view");
        assert_eq!(directory.release_mapping(Mapping::Image(again)), None);
        assert_eq!(closed(directory, section), vec![gone]);
        // A data view holds its section, as before.
        let data = directory.create_section(SectionObject::none()).unwrap();
        assert_eq!(
            directory.release_mapping(Mapping::Section(data)),
            Some(Followup::Section {
                frames: crate::mem::vm::SectionFrames::empty(),
                file_object: None,
            })
        );
    }

    /// The sweep at quiescence deletes a segment left behind as a leak, handing its frames and
    /// file object back; one a leaked image section held goes with the section.
    #[test]
    fn the_sweep_takes_leaked_segments() {
        let directory = directory();
        let segment = |directory: &mut Directory, index| {
            directory
                .create_segment(ImageSegment {
                    frames: crate::mem::vm::SectionFrames::empty(),
                    file_object: ObjectId {
                        kind: ObjectType::File,
                        index,
                        generation: 0,
                    },
                    image_base: 0x1000_0000,
                    size: 0x1000,
                })
                .unwrap()
        };
        let held = segment(directory, 1);
        image_section(directory, held);
        segment(directory, 2);
        let (leaks, followups) = sweep(directory);
        assert_eq!(leaks, 2, "the section and the lone segment");
        assert_eq!(followups.len(), 2);
        assert_eq!(directory.segments.live(), 0);
    }

    /// A file object's last handle is its cleanup (share access, delete-on-close), and its last
    /// reference its close: a mapping's reference holds it between the two. It is no waitable.
    #[test]
    fn a_file_object_cleans_up_then_closes() {
        let directory = directory();
        let id = directory
            .create_file(
                crate::fs::file::FileRecordId::at(4),
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
        published(directory, id);
        assert!(directory.handle_opened(id), "a duplicate");
        assert_eq!(closed(directory, id), vec![], "another handle remains");
        assert!(directory.reference(id), "a section's");
        assert_eq!(
            closed(directory, id),
            vec![Followup::FileCleanup {
                record: crate::fs::file::FileRecordId::at(4),
                access: 1,
                share: 7,
                delete_on_close: true,
            }]
        );
        assert_eq!(
            directory.dereference(id),
            Some(Followup::FileClose {
                record: crate::fs::file::FileRecordId::at(4)
            })
        );
        // Both at once when nothing else holds it.
        let five = crate::fs::file::FileRecordId::at(5);
        let id = directory.create_file(five, 0, 0x80, 0).unwrap();
        published(directory, id);
        assert_eq!(
            closed(directory, id),
            vec![
                Followup::FileCleanup {
                    record: five,
                    access: 0,
                    share: 0,
                    delete_on_close: false,
                },
                Followup::FileClose { record: five },
            ]
        );
    }
}
