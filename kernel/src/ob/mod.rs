//! The object manager: every kernel object a handle can name, with its lifetime.
//!
//! Objects live in typed pools, global to the kernel rather than to a process:
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
//! live object, compares exactly (Win32 object names are case-sensitive; a caller's
//! OBJ_CASE_INSENSITIVE folds the comparison), and goes with the bound object's last handle. A
//! name is kept as the UTF-16 units its creator's UNICODE_STRING gave, whatever they are.
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
//! Most kinds live in slot pools ([`crate::slots`]) that grow a page at a time from the nonpaged
//! pool and keep their peak, so a record never moves; their only bound is the u16 index, and a
//! create that finds no page fails as the platform's out-of-memory would. The dispatcher objects
//! and the processes keep fixed pools until they move too (a create past one fails the same way).
//! A slot pool's first generation is 1 and moves on at the delete, so no live object's id carries
//! generation 0.

pub mod access;
pub mod security;

use core::sync::atomic::{fence, AtomicU32, Ordering};

use rtl::array_vec::ArrayVec;
use security::Sd;

use crate::level::Dispatch;
use crate::sched::dispatcher::Dispatcher;
use crate::sched::event::EventKind;
use crate::sched::mutex::MutexId;
use crate::sched::thread::ThreadId;
use crate::sched::timer::TimerId;
use crate::sched::wait::{WaitableId, MAXIMUM_WAIT_OBJECTS};
use crate::slots::{per_page, Id, KernelId, Record, Slots};
use crate::status::NtStatus;

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
    /// A device context: win32k's, a screen DC (see [`crate::win32k::dc`]).
    Dc,
    /// A brush: win32k's, a logical brush a DC selects (see [`crate::win32k::brush`]).
    Brush,
    /// A bitmap: win32k's, a device-dependent bitmap or a DIB section a memory DC selects (see
    /// [`crate::win32k::bitmap`]).
    Bitmap,
    /// A font object: win32k's, a LOGFONT (see [`crate::win32k::fonts`]).
    Font,
    /// A region: win32k's, its rectangles (see [`crate::win32k::region`]).
    Region,
    /// A token: a process's, made at its first open (see [`crate::se`]).
    Token,
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
    /// at the object's own index. None for a section, a file object (a wait on it waits on the
    /// event embedded in its record: [`crate::fs::file::FileObject::completion`]), the directory, a
    /// window station, a desktop, a key, a DC, a font or a token. The id's liveness is the caller's
    /// to know (a reference it holds).
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
            | ObjectType::Key
            | ObjectType::Dc
            | ObjectType::Brush
            | ObjectType::Bitmap
            | ObjectType::Font
            | ObjectType::Region
            | ObjectType::Token => None,
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
#[cfg_attr(not(test), allow(unused_imports))]
pub use rtl::nt::access::EVENT_ALL_ACCESS;
pub use rtl::nt::access::{PROCESS_ALL_ACCESS, SECTION_ALL_ACCESS, THREAD_ALL_ACCESS};

/// GetExitCodeProcess's and GetExitCodeThread's answer for one still running.
pub const STILL_ACTIVE: u32 = 259;

/// How many events can exist at once.
pub const EVENTS: usize = 256;
/// How many semaphores can exist at once.
pub const SEMAPHORES: usize = 64;
/// How many mutexes can exist at once.
pub const MUTEXES: usize = 64;
/// How many waitable timers can exist at once, across every process: a full table refuses a
/// create (STATUS_INSUFFICIENT_RESOURCES, Windows 2000's answer when its pool has no room for the
/// object).
pub const TIMERS: usize = 256;
/// How many image segments may be live before a new one makes room by purging the least recently
/// cached ([`Directory::make_room_for_segment`]): the bound on the image cache, two for each
/// process record. Not a cap: while every segment is active, a new one is made all the same.
pub const SEGMENTS: usize = 2 * PROCESSES;
/// How many thread records exist, across every process: any process's thread takes any free
/// record, main thread or created. A record's index is not its thread's ordinal (the process's own
/// numbering, which places its TEB: see [`crate::process::ordinals`]). Room for two processes at
/// nearly their full thread counts.
pub const THREADS: usize = 128;

/// A set of thread records, by index: a bit each.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ThreadRecordSet([u32; THREADS.div_ceil(32)]);

impl ThreadRecordSet {
    /// No record.
    const EMPTY: ThreadRecordSet = ThreadRecordSet([0; THREADS.div_ceil(32)]);

    /// Add record `index`.
    fn insert(&mut self, index: u16) {
        self.0[index as usize / 32] |= 1 << (index % 32);
    }

    /// The records in the set, lowest first.
    fn iter(self) -> impl Iterator<Item = u16> {
        (0..THREADS as u16)
            .filter(move |&index| self.0[index as usize / 32] & (1 << (index % 32)) != 0)
    }
}
/// How many processes can exist at once: the process pool's records ([`crate::process::pool`]),
/// one process object each.
pub const PROCESSES: usize = crate::process::MAX_PROCESSES;
/// The longest object name: MAX_PATH.
pub const MAX_NAME: usize = 260;

/// An object's counts: every reference (the pointer count), and the handles among them.
///
/// Both are atomic, as Windows 2000's PointerCount is changed with interlocked operations
/// (ObReferenceObject, ObDereferenceObject; from memory). The protocol, which every change goes
/// through one method of this type for:
///
/// - **A holder's reference** ([`Counts::add_held`]): whoever holds a reference may take another
///   without the directory's lock. The count is at least the holder's, so it cannot reach zero
///   meanwhile.
/// - **A look-up's reference** ([`Counts::try_add`]): a reference found by id, handle or name is
///   taken under the directory's lock, which keeps the record the object's (its generation), and
///   refuses a zero count. An object whose last reference went is *dying*: its deleter is on its
///   way to the lock, and to every look-up it is gone already (Windows XP's ObReferenceObjectSafe's
///   rule). Nothing brings a dying object back, so exactly one thread sees the count reach zero.
/// - **A release** ([`Counts::release`]): a decrement, with Release ordering, that needs no lock
///   unless it is the last. The last one is the deletion's first phase; its second runs under the
///   directory's lock ([`Directory::delete_unreferenced`]), which re-checks before deleting: the id
///   still names the record's object (no one deleted it first) and its count is still zero (an
///   image segment's, which a look-up may take back from its cache, [`Counts::revive`], may not
///   be).
/// - **An image segment's** count changes only under the directory's lock: a cached segment is live
///   at zero, and a look-up takes it back ([`Counts::revive`]), so its zero is seen more than once
///   and only the lock orders those sightings with its caching.
/// - **Handles** change only under the directory's lock, with the handle table's insert or close
///   (Windows 2000 changes HandleCount under its object-type mutex; from memory): a handle's
///   reference is a look-up's, and the last close decides the name's and a file object's cleanup in
///   the same hold. They are atomic so a reader outside the lock sees a whole value.
///
/// Today every caller is inside the directory's lock, so the two phases of a deletion run in one
/// hold. Taking a holder's reference, or dropping a reference that is not the last, outside it
/// needs the counts reachable without the directory's `&mut` (multicore phase 1); the protocol is
/// already the one that allows it.
#[derive(Debug)]
struct Counts {
    pointers: AtomicU32,
    handles: AtomicU32,
}

impl Counts {
    const fn new(pointers: u32, handles: u32) -> Counts {
        Counts {
            pointers: AtomicU32::new(pointers),
            handles: AtomicU32::new(handles),
        }
    }

    /// A new object's: its creator's reference, no handle.
    const fn created() -> Counts {
        Counts::new(1, 0)
    }

    /// A free record's.
    const fn none() -> Counts {
        Counts::new(0, 0)
    }

    /// A deleted object's record counts nothing, whatever held it (the sweep deletes leaks).
    fn clear(&self) {
        self.pointers.store(0, Ordering::Relaxed);
        self.handles.store(0, Ordering::Relaxed);
    }

    /// The (pointer, handle) counts as they stand.
    fn snapshot(&self) -> (u32, u32) {
        (
            self.pointers.load(Ordering::Acquire),
            self.handles.load(Ordering::Acquire),
        )
    }

    /// Whether the last reference went: the object is dying (or, for an image segment, cached).
    fn unreferenced(&self) -> bool {
        self.pointers.load(Ordering::Acquire) == 0
    }

    /// Take another reference for a holder of one: no lock needed.
    fn add_held(&self) {
        let before = self.pointers.fetch_add(1, Ordering::Relaxed);
        debug_assert!(
            before != 0,
            "only a holder adds a reference without a look-up"
        );
        debug_assert!(before != u32::MAX, "the pointer count overflows");
    }

    /// Take a reference for a look-up, under the directory's lock: none for a dying object.
    fn try_add(&self) -> bool {
        let mut count = self.pointers.load(Ordering::Relaxed);
        loop {
            if count == 0 {
                return false;
            }
            debug_assert!(count != u32::MAX, "the pointer count overflows");
            match self.pointers.compare_exchange_weak(
                count,
                count + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(now) => count = now,
            }
        }
    }

    /// Take a reference on an image segment, cached (no reference) or not, under the directory's
    /// lock: a cached segment is live, its record kept for its file's next image section.
    fn revive(&self) {
        let before = self.pointers.fetch_add(1, Ordering::Relaxed);
        debug_assert!(before != u32::MAX, "the pointer count overflows");
    }

    /// Take the deletion of a process object whose own reference alone holds it (no handle, no
    /// other reference): its count goes from one to two, the claim's reference. Under the
    /// directory's lock (the handles are stable there); false when anything else holds it.
    fn claim_sole(&self) -> bool {
        self.handles.load(Ordering::Relaxed) == 0
            && self
                .pointers
                .compare_exchange(1, 2, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }

    /// Drop a reference: whether it was the last. The decrement orders the holder's writes before
    /// it (Release), and the last one sees every other holder's (Acquire), as the deletion that
    /// follows must.
    #[must_use = "the last reference's release deletes the object"]
    fn release(&self) -> bool {
        let before = self.pointers.fetch_sub(1, Ordering::Release);
        debug_assert!(before != 0, "a reference is released once");
        if before != 1 {
            return false;
        }
        fence(Ordering::Acquire);
        true
    }

    /// A handle was opened on the object, under the directory's lock: one handle more, and its
    /// reference (a look-up's: none for a dying object).
    fn open_handle(&self) -> bool {
        if !self.try_add() {
            return false;
        }
        self.handles.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// A handle was closed, under the directory's lock: whether it was the last. Its reference is
    /// the caller's to release next.
    #[must_use = "the last handle's close drops the name"]
    fn close_handle(&self) -> bool {
        let before = self.handles.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(before != 0, "a handle closes once");
        before == 1
    }
}

/// One record's header in a fixed pool (the dispatcher objects' and the processes'): whether it
/// holds a live object, its generation, the object's counts, and its security descriptor.
#[derive(Debug)]
pub struct Header {
    live: bool,
    generation: u16,
    counts: Counts,
    /// The object's security descriptor (see [`security`]).
    sd: Sd,
}

impl Header {
    const fn dead() -> Self {
        Header {
            live: false,
            generation: 0,
            counts: Counts::none(),
            sd: Sd::NULL_DACL,
        }
    }

    /// Whether the header holds the live object of `generation`.
    fn names(&self, generation: u16) -> bool {
        self.live && self.generation == generation
    }
}

/// Take a free record among `headers` in `range` for a new object: the lowest one holding no live
/// object. The object starts with one reference (its creator's) and no handle, and carries the
/// security descriptor the current create captured (the default when it captured none). None when
/// the range is exhausted. The record itself is the caller's to renew.
fn allocate(headers: &mut [Header], range: core::ops::Range<usize>, fallback: Sd) -> Option<u16> {
    let end = range.end.min(headers.len());
    let index = (range.start..end).find(|&index| !headers[index].live)?;
    let header = &mut headers[index];
    header.live = true;
    header.counts = Counts::created();
    header.sd = security::take_pending().unwrap_or(fallback);
    Some(index as u16)
}

/// A fixed pool of records of one kind, each behind its header: the dispatcher objects' (headers
/// alone, `T` is `()`: their bodies are the dispatcher database's) and the processes', until they
/// move onto slot pools as the other kinds have ([`ObSlots`]).
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
    fn allocate_in(&mut self, range: core::ops::Range<usize>, fallback: Sd) -> Option<u16> {
        allocate(&mut self.headers, range, fallback)
    }

    /// Whether the record at `index` holds a live object.
    fn is_live_at(&self, index: u16) -> bool {
        self.headers[index as usize].live
    }

    // The untyped paths' view of the pool: the counts of the live object `index` and
    // `generation` name, the lowest live record, a record's generation, and a record's death.

    fn counts(&self, index: u16, generation: u16) -> Option<&Counts> {
        let header = self.headers.get(index as usize)?;
        header.names(generation).then_some(&header.counts)
    }

    fn lowest_live(&self) -> Option<u16> {
        let index = self.headers.iter().position(|header| header.live)?;
        Some(index as u16)
    }

    fn generation_at(&self, index: u16) -> u16 {
        self.headers[index as usize].generation
    }

    fn kill(&mut self, index: u16) {
        let header = &mut self.headers[index as usize];
        header.live = false;
        header.counts = Counts::none();
        header.generation = header.generation.wrapping_add(1);
        header.sd = Sd::NULL_DACL;
    }

    /// How many records hold a live object.
    #[cfg(test)]
    fn live(&self) -> usize {
        self.headers.iter().filter(|header| header.live).count()
    }
}

/// An object's record in its kind's slot pool: its counts, its security descriptor, and its body.
/// The pool's slot holds the liveness and the generation (the slot's uniqueness count: 1 first,
/// moved on at the delete, never 0), and its chunk keeps the record at its address for the
/// kernel's life (a file object's lock event is named by its address).
pub struct ObRecord<B> {
    counts: Counts,
    /// The object's security descriptor (see [`security`]).
    sd: Sd,
    body: B,
}

/// A kind's slot pool: a page of records at a time, from the nonpaged pool, made as the kind
/// needs them and kept at its peak. Its only bound is the u16 index (65,535 objects of the kind),
/// a representation limit memory reaches first; a create that finds no page fails as a full pool
/// did (STATUS_INSUFFICIENT_RESOURCES).
type ObSlots<B, const PER: usize> = Slots<ObRecord<B>, KernelId<B>, PER>;

/// The ob id of the slot `id` of a pool of `kind`.
fn object_id<B>(kind: ObjectType, id: Id<B>) -> ObjectId {
    ObjectId {
        kind,
        index: id.index,
        generation: id.uniq,
    }
}

/// The slot id an ob id names in its kind's pool.
fn slot_id<B>(id: ObjectId) -> Id<B> {
    Id::new(id.index, id.generation)
}

/// The slot id a segment id names in the segments' pool.
fn segment_slot(id: SegmentId) -> Id<ImageSegment> {
    Id::new(id.index, id.generation)
}

/// The pages the slot pools grow from: the kernel's ([`crate::slots::KERNEL_PAGES`]), or a
/// test's own.
#[cfg(not(test))]
fn pages() -> &'static impl crate::slots::Pages {
    &crate::slots::KERNEL_PAGES
}

#[cfg(test)]
fn pages() -> &'static crate::slots::HostPages {
    tests::pages()
}

/// A new object's record in `pool`, holding its creator's reference: its id and its record, for
/// the caller to fill. The record carries the security descriptor the current create captured
/// (the default when it captured none). None when no page is left for the pool to grow (or its u16
/// index is spent).
fn allocate_record<B, const PER: usize>(
    pool: &mut ObSlots<B, PER>,
    kind: ObjectType,
) -> Option<(ObjectId, &mut ObRecord<B>)>
where
    ObRecord<B>: Record,
{
    let (id, record) = pool.allocate_or_grow(0, pages()).ok()?;
    record.counts = Counts::created();
    record.sd = security::take_pending().unwrap_or_else(|| security::default_sd(kind));
    Some((object_id(kind, id), record))
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
/// made from — the file stays open, counted as mapped, while it lives.
///
/// It is active while an image section or a view references it. Its last reference leaves it
/// cached, as Windows 2000 keeps an image's control area once its last view goes: still its file's,
/// its frames parked on Standby ([`Followup::Park`]) where the allocator may take them, so the
/// file's next image section revives it and takes back the frames still its own without reading
/// the file. A cached segment is purged — its frames and its file given back — when its file is
/// cut, overwritten, written or deleted ([`Directory::purge_segment`]), when the table needs its
/// record for another image ([`Directory::make_room_for_segment`], the least recently cached
/// first), and at shutdown; it outlives quiescence, its file object and record the cache's, not
/// leaks ([`Directory::image_cache_settled`]). An active segment's file cannot be opened for
/// writing (`nt::section::flush_image_for_write`); a segment whose file changed all the same (a
/// write through a handle opened before the image was mapped) while it was active is
/// detached: no longer its file's, its last reference deletes it.
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
    /// Whether it is no longer its file's (the file changed while it was active): its last
    /// reference deletes it instead of caching it.
    pub detached: bool,
    /// Whether its frames are parked on Standby (a cached segment's, once its caching finished).
    pub parked: bool,
    /// Its place in the order the cached segments were cached in: the least recent is the first
    /// to give its record up.
    cached_at: u32,
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
            detached: false,
            parked: false,
            cached_at: 0,
        }
    }

    /// An active segment of `file_object`'s image, its frames not made yet.
    pub const fn new(file_object: ObjectId, image_base: u32, size: u32) -> Self {
        ImageSegment {
            file_object,
            image_base,
            size,
            ..ImageSegment::none()
        }
    }

    /// How many pages the image spans as mapped.
    pub fn pages(&self) -> u32 {
        self.size.div_ceil(crate::mem::vm::PAGE)
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

/// The named objects' directory's body: none (`\BaseNamedObjects` is the one there is).
#[derive(Clone, Copy)]
pub struct DirectoryObject;

/// What a caller must finish once an object's last handle or last reference went: the work outside
/// the object manager's reach, finished once the directory's lock is released ([`finish`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Followup {
    /// A section or an image segment was deleted: its frames (taken out of its record) and the
    /// file object a file's section or a segment held are the caller's to release. A cached
    /// segment's frames are parked: `parked` is then its image's page count.
    Section {
        frames: crate::mem::vm::SectionFrames,
        file_object: Option<ObjectId>,
        parked: Option<u32>,
    },
    /// An image segment's last reference went: it stays cached, its frames to park on Standby
    /// (unless it is referenced again first).
    Park(SegmentId),
    /// A file object's last handle closed (its cleanup), for the device it is open on: a disk
    /// file's share access leaves the file's record, the byte-range locks the object holds go, its
    /// delete-on-close marks the file delete-pending, and the last cleanup of a delete-pending
    /// file deletes it.
    FileCleanup {
        object: ObjectId,
        context: crate::fs::file::Context,
        access: u8,
        share: u8,
        delete_on_close: bool,
    },
    /// A file object was deleted (its close), for the device it is open on: a disk file's
    /// reference on its record goes.
    FileClose { context: crate::fs::file::Context },
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

/// The units of `prefix`, an ASCII string.
const fn ascii_units<const N: usize>(prefix: &[u8; N]) -> [u16; N] {
    let mut units = [0u16; N];
    let mut index = 0;
    while index < N {
        units[index] = prefix[index] as u16;
        index += 1;
    }
    units
}

/// The session prefixes, `Global\` and `Local\`, as units.
const GLOBAL_PREFIX: [u16; 7] = ascii_units(b"Global\\");
const LOCAL_PREFIX: [u16; 6] = ascii_units(b"Local\\");

/// A program's object name as the namespace keeps it: without a `Global\` or `Local\` prefix.
/// There is one session, so the global namespace and the session's local one are the same
/// directory (Windows 2000 with Terminal Services keeps `\Sessions\<n>\BaseNamedObjects` apart).
/// The prefixes are matched as spelled.
pub fn namespace_name(name: &[u16]) -> &[u16] {
    name.strip_prefix(&GLOBAL_PREFIX[..])
        .or_else(|| name.strip_prefix(&LOCAL_PREFIX[..]))
        .unwrap_or(name)
}

/// Whether two names are the same one: unit for unit, or, `case_insensitive` (the caller's
/// OBJ_CASE_INSENSITIVE), each unit upper-cased as the kernel's case-insensitive comparisons fold
/// it ([`rtl::path::upcase`]).
fn same_name(a: &[u16], b: &[u16], case_insensitive: bool) -> bool {
    if case_insensitive {
        a.len() == b.len()
            && a.iter()
                .zip(b)
                .all(|(&x, &y)| rtl::path::upcase(x) == rtl::path::upcase(y))
    } else {
        a == b
    }
}

/// One name-table entry: the name's UTF-16 units, as the caller's UNICODE_STRING gave them.
#[derive(Clone, Copy)]
struct NameEntry {
    object: Option<ObjectId>,
    length: u16,
    units: [u16; MAX_NAME],
}

impl NameEntry {
    const fn free() -> Self {
        NameEntry {
            object: None,
            length: 0,
            units: [0; MAX_NAME],
        }
    }

    fn name(&self) -> &[u16] {
        &self.units[..self.length as usize]
    }
}

// SAFETY: writes a whole entry.
unsafe impl Record for NameEntry {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(NameEntry::free()) };
    }
}

/// The names' pool: one namespace, a page of entries at a time.
type Names = Slots<NameEntry, KernelId<NameEntry>, { per_page::<NameEntry>() }>;

/// Why a name could not be bound.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NameError {
    /// The name is longer than an object name may be.
    TooLong,
    /// No page was left for the name table to grow.
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

/// The kinds' pools, in two tables. The fixed pools' rows (the dispatcher objects and the
/// processes): the kind, its pool's field, its body (`()` for a dispatcher object: the body is the
/// dispatcher database's, at the same index; a process keeps its thread ordinals here, since which
/// of them are free is its thread objects' lives), how a fresh record is made, and the capacity.
/// The slot pools' rows: the kind, its pool's field, its body and how a fresh body is made; the
/// pool holds a page of records a chunk. The tables make the [`Directory`]'s pools, its in-place
/// builder, and the matches the untyped paths (an object's counts by id, its deletion, the sweep)
/// reach a kind's pool through.
macro_rules! pools {
    (
        fixed { $($kind:ident => $pool:ident: $body:ty = $fresh:expr, $capacity:expr;)* }
        slots { $($skind:ident => $spool:ident: $sbody:ty = $sfresh:expr;)* }
    ) => {
        $(
            // SAFETY: writes a whole record.
            unsafe impl Record for ObRecord<$sbody> {
                unsafe fn write_fresh(at: *mut Self, _: u32) {
                    // SAFETY: the caller's contract.
                    unsafe {
                        at.write(ObRecord {
                            counts: Counts::none(),
                            sd: Sd::NULL_DACL,
                            body: $sfresh,
                        })
                    };
                }
            }
        )*

        /// Every object, by kind, with the image segments, the namespace and the waits'
        /// references. The dispatcher objects' pools are their headers alone: the bodies are the
        /// dispatcher database's, at the same index.
        pub struct Directory {
            $($pool: Pool<$body, $capacity>,)*
            $($spool: ObSlots<$sbody, { per_page::<ObRecord<$sbody>>() }>,)*
            segments: ObSlots<ImageSegment, { per_page::<ObRecord<ImageSegment>>() }>,
            names: Names,
            waits: [WaitReferences; THREADS],
            /// The thread records handed to a thread object since the last sweep's end (a bit per
            /// record): the only ones the sweep's end starts over (see [`Directory::sweep_end`]).
            used_threads: ThreadRecordSet,
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
                    $(addr_of_mut!((*directory).$spool).write(Slots::new());)*
                    addr_of_mut!((*directory).segments).write(Slots::new());
                    addr_of_mut!((*directory).names).write(Slots::new());
                    let waits = addr_of_mut!((*directory).waits) as *mut WaitReferences;
                    for index in 0..THREADS {
                        waits.add(index).write(WaitReferences::none());
                    }
                    addr_of_mut!((*directory).used_threads).write(ThreadRecordSet::EMPTY);
                }
            }

            /// The counts of the object `id` names, live or dying (see [`Counts`]); none for an
            /// id that names nothing.
            fn header(&self, id: ObjectId) -> Option<&Counts> {
                match id.kind {
                    $(ObjectType::$kind => self.$pool.counts(id.index, id.generation),)*
                    $(ObjectType::$skind => self
                        .$spool
                        .get(slot_id(id))
                        .map(|record| &record.counts),)*
                }
            }

            /// The security descriptor cell of the live object `id` names; none for an id that
            /// names nothing.
            fn sd_cell(&mut self, id: ObjectId) -> Option<&mut Sd> {
                match id.kind {
                    $(ObjectType::$kind => self
                        .$pool
                        .headers
                        .get_mut(id.index as usize)
                        .filter(|header| header.names(id.generation))
                        .map(|header| &mut header.sd),)*
                    $(ObjectType::$skind => self
                        .$spool
                        .get_mut(slot_id(id))
                        .map(|record| &mut record.sd),)*
                }
            }

            /// The id of the record at `index` of a fixed pool's `kind`, live or not.
            ///
            /// # Panics
            ///
            /// `kind`'s pool is a slot pool (its dead records have no id).
            fn id(&mut self, kind: ObjectType, index: u16) -> ObjectId {
                let generation = match kind {
                    $(ObjectType::$kind => self.$pool.generation_at(index),)*
                    _ => unreachable!("a fixed pool's kind"),
                };
                ObjectId {
                    kind,
                    index,
                    generation,
                }
            }

            /// The lowest live object of `kind`.
            fn lowest_live(&mut self, kind: ObjectType) -> Option<ObjectId> {
                match kind {
                    $(ObjectType::$kind => {
                        let index = self.$pool.lowest_live()?;
                        Some(self.id(kind, index))
                    })*
                    $(ObjectType::$skind => self
                        .$spool
                        .iter()
                        .next()
                        .map(|(id, _)| object_id(kind, id)),)*
                }
            }

            /// The live object `id` names is gone: its record is free, its id stale.
            fn kill(&mut self, id: ObjectId) {
                match id.kind {
                    $(ObjectType::$kind => self.$pool.kill(id.index),)*
                    $(ObjectType::$skind => {
                        let freed = self.$spool.free(slot_id(id));
                        debug_assert!(freed, "a live object's record");
                    })*
                }
            }

            /// How many objects are live, of every kind.
            #[cfg(test)]
            pub fn live_objects(&self) -> usize {
                0 $(+ self.$pool.live())* $(+ self.$spool.live() as usize)*
            }
        }
    };
}

pools! {
    fixed {
        Event => events: () = || (), EVENTS;
        Semaphore => semaphores: () = || (), SEMAPHORES;
        Mutex => mutexes: () = || (), MUTEXES;
        Timer => timers: () = || (), TIMERS;
        Thread => threads: () = || (), THREADS;
        Process => processes: crate::process::ordinals::Ordinals =
            crate::process::ordinals::Ordinals::empty, PROCESSES;
    }
    slots {
        Section => sections: SectionObject = SectionObject::none();
        File => files: crate::fs::file::FileObject = crate::fs::file::FileObject::none();
        Directory => directories: DirectoryObject = DirectoryObject;
        WindowStation => window_stations: WindowStationObject = WindowStationObject::none();
        Desktop => desktops: DesktopObject = DesktopObject::none();
        Key => keys: crate::cm::KeyBody = crate::cm::KeyBody::none();
        Dc => dcs: crate::win32k::dc::Dc = crate::win32k::dc::Dc::none();
        Brush => brushes: crate::win32k::brush::Brush = crate::win32k::brush::Brush::none();
        Bitmap => bitmaps: crate::win32k::bitmap::Bitmap = crate::win32k::bitmap::Bitmap::none();
        Font => fonts: crate::win32k::fonts::FontObject =
            crate::win32k::fonts::FontObject::none();
        Region => regions: crate::win32k::region::Region = crate::win32k::region::Region::none();
        Token => tokens: crate::se::TokenBody = crate::se::TokenBody::none();
    }
}

// SAFETY: writes a whole record.
unsafe impl Record for ObRecord<ImageSegment> {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe {
            at.write(ObRecord {
                counts: Counts::none(),
                sd: Sd::NULL_DACL,
                body: ImageSegment::none(),
            })
        };
    }
}

// SAFETY: the directory's raw pointers are the links of the file objects' embedded lock headers,
// which name waitable headers and threads of the dispatcher database, reached there only with the
// dispatch token, and the slot pools' chunk pointers, which only the directory's holder follows.
// One processor, and the directory is reached only through its lock, so whichever kernel thread
// holds it is the only one reaching its records.
unsafe impl Send for Directory {}

/// A kind whose body the directory holds in a slot pool (no dispatcher object's, nor a
/// process's): its kind, and its pool's records.
pub trait Body: Sized {
    const KIND: ObjectType;

    /// The record of the live object of the kind `id` names in `directory`.
    fn record(directory: &mut Directory, id: ObjectId) -> Option<&mut ObRecord<Self>>;

    /// A new object's record in `directory`, holding its creator's reference (see
    /// [`allocate_record`]).
    fn allocate(directory: &mut Directory) -> Option<(ObjectId, &mut ObRecord<Self>)>;
}

/// The bodies' table: each body type, its kind, its pool, and the name of its typed accessor.
macro_rules! bodies {
    ($($body:ty => $kind:ident, $pool:ident, $accessor:ident;)*) => {
        $(
            impl Body for $body {
                const KIND: ObjectType = ObjectType::$kind;

                fn record(directory: &mut Directory, id: ObjectId) -> Option<&mut ObRecord<Self>> {
                    directory.$pool.get_mut(slot_id(id))
                }

                fn allocate(directory: &mut Directory) -> Option<(ObjectId, &mut ObRecord<Self>)> {
                    allocate_record(&mut directory.$pool, Self::KIND)
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
    SectionObject => Section, sections, section;
    crate::fs::file::FileObject => File, files, file;
    WindowStationObject => WindowStation, window_stations, window_station;
    DesktopObject => Desktop, desktops, desktop;
    crate::cm::KeyBody => Key, keys, key;
    crate::win32k::dc::Dc => Dc, dcs, dc;
    crate::win32k::brush::Brush => Brush, brushes, brush;
    crate::win32k::bitmap::Bitmap => Bitmap, bitmaps, bitmap;
    crate::win32k::fonts::FontObject => Font, fonts, font;
    crate::win32k::region::Region => Region, regions, region;
    crate::se::TokenBody => Token, tokens, token;
}

impl Directory {
    /// Whether `id` names a live object: not a dying one, whose last reference went (see
    /// [`Counts`]).
    pub fn is_live(&self, id: ObjectId) -> bool {
        self.header(id).is_some_and(|counts| !counts.unreferenced())
    }

    /// Claim the deletion of the live process object `id` names when its process's own reference
    /// alone holds it — no handle, and no reference beside that one (see
    /// [`crate::process::Process`]'s object) — taking a reference for the deletion in the same
    /// hold: no second caller finds the object so meanwhile, and the object, with its record,
    /// outlives the deletion's work. Whether it was claimed.
    pub fn claim_deletion(&mut self, id: ObjectId) -> bool {
        if id.kind != ObjectType::Process {
            return false;
        }
        self.header(id).is_some_and(Counts::claim_sole)
    }

    /// A deletion claimed by [`Directory::claim_deletion`] is done: the process's own reference and
    /// the claim's go in one hold, and the object with them (a process object's deletion leaves
    /// nothing to finish).
    pub fn end_claimed_deletion(&mut self, id: ObjectId) {
        debug_assert_eq!(
            self.counts(id),
            Some((2, 0)),
            "a claimed deletion holds the object"
        );
        assert_eq!(self.dereference(id), None);
        assert_eq!(self.dereference(id), None);
    }

    /// An object's (pointer, handle) counts; none for an id that names nothing.
    pub fn counts(&self, id: ObjectId) -> Option<(u32, u32)> {
        self.header(id).map(Counts::snapshot)
    }

    /// The security descriptor of the live object `id` names, as stored (see [`security`]); none
    /// for an id that names nothing.
    pub fn sd(&mut self, id: ObjectId) -> Option<&Sd> {
        self.sd_cell(id).map(|cell| &*cell)
    }

    /// Replace the security descriptor of the live object `id` names with `sd`; false when `id`
    /// names nothing. The query/set services' seam (a later slice), so unused on the target yet.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn set_sd(&mut self, id: ObjectId, sd: Sd) -> bool {
        match self.sd_cell(id) {
            Some(cell) => {
                *cell = sd;
                true
            }
            None => false,
        }
    }

    /// The seam NtQuerySecurityObject takes: the security descriptor's bytes of the live object
    /// `id` names; none for an id that names nothing. Unused on the target until that service
    /// lands.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn security_descriptor(&mut self, id: ObjectId) -> Option<&[u8]> {
        self.sd(id).map(Sd::as_slice)
    }

    /// The seam NtSetSecurityObject takes: replace the security descriptor of the live object
    /// `id` names with `sd`. STATUS_INVALID_PARAMETER for an empty descriptor,
    /// STATUS_BUFFER_TOO_SMALL past the record's storage ([`security::MAX_SD`]),
    /// STATUS_INVALID_HANDLE for an id that names nothing. Unused on the target until that
    /// service lands.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn set_security_descriptor(&mut self, id: ObjectId, sd: &[u8]) -> Result<(), NtStatus> {
        use crate::status::{
            STATUS_BUFFER_TOO_SMALL,
            STATUS_INVALID_HANDLE,
            STATUS_INVALID_PARAMETER,
        };
        if sd.is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let stored = Sd::from_bytes(sd).ok_or(STATUS_BUFFER_TOO_SMALL)?;
        self.set_sd(id, stored)
            .then_some(())
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// The body of the live object `id` names, when it is of `T`'s kind.
    pub fn body<T: Body>(&mut self, id: ObjectId) -> Option<&mut T> {
        if id.kind != T::KIND {
            return None;
        }
        T::record(self, id).map(|record| &mut record.body)
    }

    /// A new object of `T`'s kind holding `body`, with its creator's reference; none when no page
    /// is left for its pool to grow.
    fn insert<T: Body>(&mut self, body: T) -> Option<ObjectId> {
        let (id, record) = T::allocate(self)?;
        record.body = body;
        Some(id)
    }

    // --- Creation ----------------------------------------------------------------------------

    /// A fresh event of `kind` at `signaled`, holding its creator's reference; none when the pool
    /// is exhausted.
    pub fn create_event(&mut self, kind: EventKind, signaled: bool) -> Option<ObjectId> {
        let index = self.events.allocate_in(0..EVENTS, Sd::NULL_DACL)?;
        with_bodies(|bodies| {
            bodies.renew_event(index, kind, signaled);
        });
        Some(self.id(ObjectType::Event, index))
    }

    /// A fresh semaphore at `initial` with ceiling `limit`.
    pub fn create_semaphore(&mut self, initial: i32, limit: i32) -> Option<ObjectId> {
        let index = self.semaphores.allocate_in(0..SEMAPHORES, Sd::NULL_DACL)?;
        with_bodies(|bodies| {
            bodies.renew_semaphore(index, initial, limit);
        });
        Some(self.id(ObjectType::Semaphore, index))
    }

    /// A fresh, free mutex.
    pub fn create_mutex(&mut self) -> Option<ObjectId> {
        let index = self.mutexes.allocate_in(0..MUTEXES, Sd::NULL_DACL)?;
        with_bodies(|bodies| {
            bodies.renew_mutex(index);
        });
        Some(self.id(ObjectType::Mutex, index))
    }

    /// A fresh, unarmed, unsignaled waitable timer.
    pub fn create_timer(&mut self, manual_reset: bool) -> Option<ObjectId> {
        let index = self.timers.allocate_in(0..TIMERS, Sd::NULL_DACL)?;
        with_bodies(|bodies| {
            bodies.renew_waitable_timer(index, manual_reset);
        });
        Some(self.id(ObjectType::Timer, index))
    }

    /// A thread record for a new thread object, in `range`. The record is returned as it was left;
    /// the caller renews it ([`Directory::renew_thread`]). Holds the thread's own reference,
    /// released when the thread ends.
    pub fn create_thread_in(&mut self, range: core::ops::Range<usize>) -> Option<ObjectId> {
        let index = self.threads.allocate_in(range, Sd::NULL_DACL)?;
        self.used_threads.insert(index);
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
        let index = self
            .processes
            .allocate_in(0..PROCESSES, security::default_sd(ObjectType::Process))?;
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
    /// made with it). None when no page is left for the pool to grow.
    pub fn create_segment(&mut self, segment: ImageSegment) -> Option<SegmentId> {
        let (id, record) = self.segments.allocate_or_grow(0, pages()).ok()?;
        record.counts = Counts::created();
        // A segment is no object a handle names: no captured descriptor, the default.
        record.sd = Sd::NULL_DACL;
        record.body = segment;
        Some(SegmentId {
            index: id.index,
            generation: id.uniq,
        })
    }

    /// The live image segment `id` names.
    pub fn segment(&mut self, id: SegmentId) -> Option<&mut ImageSegment> {
        self.segments
            .get_mut(segment_slot(id))
            .map(|record| &mut record.body)
    }

    /// Take a reference on the image segment `id`, cached or not; false when it names nothing.
    pub fn reference_segment(&mut self, id: SegmentId) -> bool {
        self.segment_header(id).map(Counts::revive).is_some()
    }

    /// Drop a reference on the image segment `id`. The last one leaves it cached, its frames for
    /// the caller to park ([`Followup::Park`]); a detached segment's deletes it, its frames and the
    /// file object it held left to the caller.
    ///
    /// The last reference's release is the first phase; the second re-checks, as an object's
    /// deletion does ([`Directory::delete_unreferenced`]): an active segment (one a look-up took
    /// back, [`Directory::reference_segment`]) is neither cached nor deleted. A segment's count
    /// changes only under the lock (see [`Counts`]), so both phases share this hold.
    pub fn dereference_segment(&mut self, id: SegmentId) -> Option<Followup> {
        if !self.segment_header(id)?.release() {
            return None;
        }
        self.segment_unreferenced(id)
    }

    /// The second phase of an image segment's last release, under the directory's lock: unless
    /// it was taken back meanwhile (or deleted: a purge), it is cached or, detached, deleted.
    fn segment_unreferenced(&mut self, id: SegmentId) -> Option<Followup> {
        if !self.segment_header(id)?.unreferenced() {
            return None;
        }
        if self.segment(id)?.detached {
            return Some(self.delete_segment(id));
        }
        let cached_at = self.cached_segments().map(|(_, at)| at + 1).max();
        self.segment(id)?.cached_at = cached_at.unwrap_or(0);
        Some(Followup::Park(id))
    }

    /// The cached segments (live, no reference): their ids and when they were cached.
    fn cached_segments(&self) -> impl Iterator<Item = (SegmentId, u32)> + '_ {
        self.segments
            .iter()
            .filter(|(_, record)| record.counts.unreferenced())
            .map(|(id, record)| {
                let id = SegmentId {
                    index: id.index,
                    generation: id.uniq,
                };
                (id, record.body.cached_at)
            })
    }

    /// Whether `id` names a cached segment: its file's still, no reference holding it.
    pub fn segment_cached(&mut self, id: SegmentId) -> bool {
        self.segment_header(id).is_some_and(Counts::unreferenced)
    }

    /// Purge the image segment `id` because its file changes (Windows 2000's
    /// MmFlushImageSection): a cached one is deleted, its frames and file left to the caller; an
    /// active one is detached from its file, deleted with its last reference (see
    /// [`ImageSegment`]).
    pub fn purge_segment(&mut self, id: SegmentId) -> Option<Followup> {
        if self.segment_header(id)?.unreferenced() {
            return Some(self.delete_segment(id));
        }
        self.segment(id)?.detached = true;
        None
    }

    /// Whether the image cache may outlive quiescence: every cached segment's file object is the
    /// segment's alone (one reference, no handle) and `record_settled` holds for it (its file's
    /// record held by that object alone). Anything else holding a cached image's file is a leak,
    /// for the sweep to find once the cache is purged.
    pub fn image_cache_settled(
        &self,
        mut record_settled: impl FnMut(&crate::fs::file::FileObject) -> bool,
    ) -> bool {
        self.cached_files().all(|file| {
            self.files.get(slot_id(file)).is_some_and(|record| {
                record.counts.snapshot() == (1, 0) && record_settled(&record.body)
            })
        })
    }

    /// The file objects the cached segments hold.
    fn cached_files(&self) -> impl Iterator<Item = ObjectId> + '_ {
        self.segments
            .iter()
            .filter(|(_, record)| record.counts.unreferenced())
            .map(|(_, record)| record.body.file_object)
    }

    /// Whether a cached segment holds the file record `record` open (through its file object):
    /// the record outlives quiescence with the cache.
    pub fn caches_record(&self, record: crate::fs::file::FileRecordId) -> bool {
        self.cached_files().any(|file| {
            self.files
                .get(slot_id(file))
                .is_some_and(|object| object.body.disk() == Some(record))
        })
    }

    /// The frames the cached segments hold outside the allocator's lists, once each is parked (as
    /// every one is at quiescence: its caching's follow-up parks it): their frame tables. The
    /// frames they parked wait on Standby, which the allocator counts as available.
    pub fn cached_frames(&self) -> u32 {
        self.segments
            .iter()
            .filter(|(_, record)| record.counts.unreferenced())
            .map(|(_, record)| record.body.frames.tables_held())
            .sum()
    }

    /// Purge the next cached segment (at quiescence, or a volume's end), none once none is left.
    pub fn purge_next_cached(&mut self) -> Option<Followup> {
        let (id, _) = self.cached_segments().next()?;
        Some(self.delete_segment(id))
    }

    /// Make room for a new segment once [`SEGMENTS`] are live, the image cache's bound: the least
    /// recently cached segment is purged, its frames and file left to the caller. None while
    /// fewer are live, or when every segment is active (the new one is made all the same: the
    /// pool grows).
    pub fn make_room_for_segment(&mut self) -> Option<Followup> {
        if (self.segments.live() as usize) < SEGMENTS {
            return None;
        }
        let (id, _) = self.cached_segments().min_by_key(|&(_, at)| at)?;
        Some(self.delete_segment(id))
    }

    /// Delete the live image segment `id`: its record is free and its ids stale.
    fn delete_segment(&mut self, id: SegmentId) -> Followup {
        let record = self
            .segments
            .get_mut(segment_slot(id))
            .expect("deleting a live segment");
        let segment = core::mem::replace(&mut record.body, ImageSegment::none());
        record.counts = Counts::none();
        self.segments.free(segment_slot(id));
        Followup::Section {
            frames: segment.frames,
            file_object: Some(segment.file_object),
            parked: segment.parked.then(|| segment.pages()),
        }
    }

    fn segment_header(&self, id: SegmentId) -> Option<&Counts> {
        self.segments
            .get(segment_slot(id))
            .map(|record| &record.counts)
    }

    /// A view went: drop its reference on what it mapped (the last one deletes it).
    pub fn release_mapping(&mut self, mapping: Mapping) -> Option<Followup> {
        match mapping {
            Mapping::Section(id) => self.dereference(id),
            Mapping::Image(id) => self.dereference_segment(id),
        }
    }

    /// A file object open on `context` (a device and its context there), opened for `access` (as
    /// the share check reads it; `granted` the file rights) and allowing `share`.
    pub fn create_file(
        &mut self,
        context: crate::fs::file::Context,
        access: u8,
        granted: u32,
        share: u8,
    ) -> Option<ObjectId> {
        let id = self.insert(crate::fs::file::FileObject::new(
            context, access, granted, share,
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

    /// A device context in the state `body` holds; none when the pool is exhausted.
    pub fn create_dc(&mut self, body: crate::win32k::dc::Dc) -> Option<ObjectId> {
        self.insert(body)
    }

    /// A brush of `body`'s kind and colors; none when the pool is exhausted.
    pub fn create_brush(&mut self, body: crate::win32k::brush::Brush) -> Option<ObjectId> {
        self.insert(body)
    }

    /// A bitmap described by `body`; none when the pool is exhausted.
    pub fn create_bitmap(&mut self, body: crate::win32k::bitmap::Bitmap) -> Option<ObjectId> {
        self.insert(body)
    }

    /// Whether a live DC other than `except` holds the bitmap `bitmap` selected.
    pub fn bitmap_selected(&mut self, bitmap: ObjectId, except: Option<ObjectId>) -> bool {
        self.dcs.iter().any(|(dc, record)| {
            except.is_none_or(|except| except.index != dc.index)
                && record.body.bitmap_object == Some(bitmap)
        })
    }

    /// A region holding `body`'s rectangles (its block, if any, the region's from now on); none
    /// when the pool is exhausted.
    pub fn create_region(&mut self, body: crate::win32k::region::Region) -> Option<ObjectId> {
        self.insert(body)
    }

    /// A font object holding `body`'s LOGFONT; none when the pool is exhausted.
    pub fn create_font(&mut self, body: crate::win32k::fonts::FontObject) -> Option<ObjectId> {
        self.insert(body)
    }

    /// The token the process `process` names holds, if any.
    fn held_token(&self, process: ObjectId) -> Option<ObjectId> {
        self.tokens
            .iter()
            .find(|(_, record)| record.body.owner == Some(process))
            .map(|(id, _)| object_id(ObjectType::Token, id))
    }

    /// The token of the process `process` names: the one it holds, or a new one made for it (none
    /// when no page is left for the pool to grow). A new token's creator's reference is the
    /// process's, which it holds until it lets go of the token
    /// ([`Directory::take_process_token`]).
    pub fn process_token(&mut self, process: ObjectId) -> Option<ObjectId> {
        match self.held_token(process) {
            Some(id) => Some(id),
            None => self.insert(crate::se::TokenBody::of(process)),
        }
    }

    /// A token of no process holding `body` (a duplicate), with its creator's reference; none when
    /// the pool is exhausted.
    pub fn create_token(&mut self, body: crate::se::TokenBody) -> Option<ObjectId> {
        self.insert(body)
    }

    /// The process `process` names lets go of its token, if it holds one: the token no longer
    /// names it, and the process's reference on it is the caller's to drop (the token lives on
    /// while handles to it are open).
    pub fn take_process_token(&mut self, process: ObjectId) -> Option<ObjectId> {
        let id = self.held_token(process)?;
        self.token(id).expect("a live token").owner = None;
        Some(id)
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

    /// The live process object's thread ordinals.
    pub fn ordinals(&mut self, id: ObjectId) -> Option<&mut crate::process::ordinals::Ordinals> {
        let index = self.body_index(id, ObjectType::Process)?;
        Some(&mut self.processes.records[index as usize])
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

    /// The thread object whose client id is `thread_id`, among the threads that have not ended of
    /// every process (client ids are unique across processes and threads); none when no such
    /// thread has it — as on Windows 2000, an ended thread's id names nothing any more, even while
    /// a handle holds its object.
    pub fn thread_by_id(&mut self, thread_id: u32) -> Option<ObjectId> {
        with_bodies(|bodies| {
            (0..THREADS as u16).find_map(|index| {
                let id = self.id(ObjectType::Thread, index);
                let thread = bodies.thread(self.thread(id)?);
                let found = thread.thread_id() == thread_id
                    && thread.state() != crate::sched::thread::ThreadState::Terminated;
                found.then_some(id)
            })
        })
    }

    // --- Counts --------------------------------------------------------------------------------

    /// Take a reference on `id`, a look-up's (see [`Counts`]); false when it names nothing, or an
    /// object whose last reference went.
    pub fn reference(&mut self, id: ObjectId) -> bool {
        self.header(id).is_some_and(Counts::try_add)
    }

    /// Take another reference on `id` for a holder of one (see [`Counts`]): no look-up, and no
    /// `&mut`, since the holder's reference keeps the object.
    ///
    /// # Panics
    ///
    /// `id` names nothing: the caller holds no reference.
    pub fn reference_held(&self, id: ObjectId) {
        self.header(id).expect("a held object lives").add_held();
    }

    /// Drop a reference on `id`; the last one deletes the object. Returns what the caller must
    /// finish for a deleted object.
    ///
    /// The release is the deletion's first phase, which needs no lock; the deletion itself is the
    /// second, [`Directory::delete_unreferenced`], under the lock. Both run in this one hold.
    pub fn dereference(&mut self, id: ObjectId) -> Option<Followup> {
        let counts = self.header(id)?;
        debug_assert!(
            {
                let (pointers, handles) = counts.snapshot();
                pointers > handles
            },
            "a reference beyond the handles' is held"
        );
        if !counts.release() {
            return None;
        }
        self.delete_unreferenced(id)
    }

    /// The second phase of an object's last release (see [`Counts`]), under the directory's lock:
    /// re-check, then delete. Nothing when `id` names nothing any more (its deletion ran already)
    /// or the object holds a reference again (none of a look-up's can: it refuses a dying object;
    /// the check is the rule's guard).
    fn delete_unreferenced(&mut self, id: ObjectId) -> Option<Followup> {
        if !self.header(id)?.unreferenced() {
            return None;
        }
        self.delete(id)
    }

    /// A handle to `id` was inserted: one handle more, and its reference (a look-up's: false,
    /// nothing counted, for a dying object or a stale id).
    pub fn handle_opened(&mut self, id: ObjectId) -> bool {
        self.header(id).is_some_and(Counts::open_handle)
    }

    /// A handle to `id` was closed: the last handle drops the object's name and cleans up a file
    /// object, and the handle's reference goes with it (the last reference deletes the object).
    /// Returns what the caller must finish, in order.
    pub fn handle_closed(&mut self, id: ObjectId) -> Followups {
        let mut followups = Followups::none();
        let Some(counts) = self.header(id) else {
            return followups;
        };
        if counts.close_handle() {
            self.forget_name(id);
            if let Some(file) = self.file(id) {
                followups.push(Some(Followup::FileCleanup {
                    object: id,
                    context: file.context,
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
    /// object its close; an owned mutex leaves its owner's list; no other
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
                        parked: None,
                    }),
                }
            }
            ObjectType::File => Some(Followup::FileClose {
                context: self.file(id).expect("deleting a live file object").context,
            }),
            ObjectType::Region => {
                // A large region's rectangles are a block of the pool, which goes with it.
                let region = core::mem::replace(
                    self.region(id).expect("deleting a live region"),
                    crate::win32k::region::Region::none(),
                );
                crate::win32k::region::release_storage(&region);
                None
            }
            ObjectType::Dc => {
                // A DC's clipping regions' blocks go with it.
                self.dc(id).expect("deleting a live DC").release_regions();
                None
            }
            ObjectType::Event
            | ObjectType::Semaphore
            | ObjectType::Thread
            | ObjectType::Process
            | ObjectType::Directory
            | ObjectType::WindowStation
            | ObjectType::Desktop
            | ObjectType::Key
            | ObjectType::Brush
            | ObjectType::Bitmap
            | ObjectType::Font
            | ObjectType::Token => None,
        };
        self.forget_name(id);
        // The sweep deletes a leak whatever holds it.
        self.header(id).expect("deleting a live object").clear();
        self.kill(id);
        followup
    }

    // --- Names -------------------------------------------------------------------------------

    /// The live object `name` binds (its session prefix aside, see [`namespace_name`]), compared
    /// exactly or, `case_insensitive` (OBJ_CASE_INSENSITIVE), folded (see [`same_name`]). A dying
    /// object's name, which its deletion is on its way to drop, binds nothing (see [`Counts`]).
    pub fn lookup_name(&self, name: &[u16], case_insensitive: bool) -> Option<ObjectId> {
        let name = namespace_name(name);
        self.names.iter().find_map(|(_, entry)| {
            entry
                .object
                .filter(|&id| same_name(entry.name(), name, case_insensitive) && self.is_live(id))
        })
    }

    /// The name `id` is bound to in the namespace, as the namespace keeps it (UTF-16 units, as
    /// its creator spelled them); none for an object without one.
    pub fn name_of(&self, id: ObjectId) -> Option<&[u16]> {
        self.names
            .iter()
            .find(|(_, entry)| entry.object == Some(id))
            .map(|(_, entry)| entry.name())
    }

    /// Bind `name` to `id` (its session prefix aside).
    pub fn bind_name(&mut self, name: &[u16], id: ObjectId) -> Result<(), NameError> {
        let name = namespace_name(name);
        if name.len() > MAX_NAME {
            return Err(NameError::TooLong);
        }
        let (_, entry) = self
            .names
            .allocate_or_grow(0, pages())
            .map_err(|_| NameError::Full)?;
        entry.object = Some(id);
        entry.length = name.len() as u16;
        entry.units[..name.len()].copy_from_slice(name);
        Ok(())
    }

    /// Forget the name bound to `id`, if any.
    fn forget_name(&mut self, id: ObjectId) {
        loop {
            let bound = self
                .names
                .iter()
                .find(|(_, entry)| entry.object == Some(id))
                .map(|(name, _)| name);
            match bound {
                Some(name) => self.names.free(name),
                None => break,
            };
        }
    }

    // --- Waits -------------------------------------------------------------------------------

    /// The wait thread record `thread` is about to enter holds `objects`, dispatcher objects and
    /// file objects (whose own event it waits on: [`crate::ob::waiting`] keeps another reference
    /// on each, so this one is never its last), for its whole life: a reference on each, released
    /// by [`Directory::release_wait`] when the wait returns — or when the thread ends without
    /// returning. False, and nothing held, when one of them is gone already (a handle another
    /// thread closed meanwhile).
    pub fn hold_wait(&mut self, thread: u16, objects: &[ObjectId]) -> bool {
        debug_assert!(self.waits[thread as usize]
            .objects
            .iter()
            .all(Option::is_none));
        debug_assert!(
            objects
                .iter()
                .all(|id| id.waitable().is_some() || id.kind == ObjectType::File),
            "a wait holds dispatcher objects and file objects"
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
            ObjectType::Dc,
            ObjectType::Brush,
            ObjectType::Bitmap,
            ObjectType::Font,
            ObjectType::Region,
            ObjectType::Token,
        ] {
            // A cached image's file object is the cache's, not a leak (see
            // `image_cache_settled`).
            let lowest = match kind {
                ObjectType::File => self
                    .files
                    .iter()
                    .map(|(id, _)| object_id(kind, id))
                    .find(|&id| !self.cached_files().any(|file| file == id)),
                kind => self.lowest_live(kind),
            };
            if let Some(id) = lowest {
                // A leaked image section's segment goes with it, not into the cache.
                let followup = match self.delete(id) {
                    Some(Followup::Park(segment)) => Some(self.delete_segment(segment)),
                    followup => followup,
                };
                return Some(Leak { followup });
            }
        }
        // The image sections went above, and every view with its process: an active segment left
        // is a leak too (a cached one is the image cache's).
        let (segment, _) = self
            .segments
            .iter()
            .find(|(_, record)| !record.counts.unreferenced())?;
        let segment = SegmentId {
            index: segment.index,
            generation: segment.uniq,
        };
        Some(Leak {
            followup: Some(self.delete_segment(segment)),
        })
    }

    /// The sweep's end: every thread record starts over, and every wait's references and every
    /// name are freed.
    ///
    /// Only the records a thread object was handed since the last sweep's end are renewed: the
    /// others have had no thread since that renewal (or the boot's empty pool), so they are as it
    /// left them, and only a thread's wait holds references. A renewal rewrites a whole record
    /// (its wait blocks, its floating-point state), so renewing all of them took about 4 ms under
    /// QEMU at every quiescent reap, most of a small process's teardown.
    pub fn sweep_end(&mut self) {
        let used = core::mem::replace(&mut self.used_threads, ThreadRecordSet::EMPTY);
        with_bodies(|bodies| {
            for index in used.iter() {
                bodies.renew_thread(ThreadId(index));
                self.waits[index as usize] = WaitReferences::none();
            }
        });
        self.names.drain(|_, _| ());
    }

    /// `\BaseNamedObjects`, the named objects' directory: made at its first open and permanent
    /// (its creator's reference is never dropped, so no process's end deletes it).
    pub fn named_objects(&mut self) -> Option<ObjectId> {
        if let Some((id, _)) = self.directories.iter().next() {
            return Some(object_id(ObjectType::Directory, id));
        }
        allocate_record(&mut self.directories, ObjectType::Directory).map(|(id, _)| id)
    }
}

/// Signal the process object whose body is at `index` with `exit_status`, once, waking its waiters
/// (no boost: the end grants none).
fn signal_process_body(index: u16, exit_status: u32) {
    with_bodies(|bodies| {
        let process = bodies.process_object_mut(index);
        process.exit_status = exit_status;
        process.waitable.get_mut().signal_state = 1;
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
    /// — and its close, each by the device the object is open on. Runs outside the directory's
    /// lock, at the passive level.
    pub fn finish(followup: Followup) {
        match followup {
            Followup::Section {
                frames,
                file_object,
                parked,
            } => {
                crate::nt::section::release_frames(frames, parked);
                if let Some(file_object) = file_object {
                    unmap_file(file_object);
                }
            }
            Followup::Park(segment) => crate::nt::section::park_segment(segment),
            Followup::FileCleanup {
                object,
                context,
                access,
                share,
                delete_on_close,
            } => crate::fs::io::cleanup(object, context, access, share, delete_on_close),
            Followup::FileClose { context } => crate::fs::io::close(context),
        }
    }

    /// A file-backed section, or an image segment, is gone: its file is mapped once less, and its
    /// reference on the file object goes (the object's close follows, when that was its last
    /// reference). Only a disk file is mapped (a section refuses any other device's).
    fn unmap_file(file_object: ObjectId) {
        let Some(file) = locked(|directory| directory.file(file_object).map(|file| file.disk()))
        else {
            return;
        };
        let record = file.expect("a mapped file is a disk file");
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
    /// sharing, its options) is never written again while it lives, and reads freely; its lock
    /// is shared state of its own, and its position and its directory search sit in a cell
    /// reached only by the lock's holder, through [`crate::fs::io::serialized`].
    pub struct Referenced<T: 'static> {
        _reference: ObRef,
        record: NonNull<T>,
    }

    impl<T: 'static> Referenced<T> {
        /// The object's identity.
        pub fn id(&self) -> ObjectId {
            self._reference.id()
        }
    }

    impl<T: 'static> core::ops::Deref for Referenced<T> {
        type Target = T;

        fn deref(&self) -> &T {
            // SAFETY: the record is a pool record of the directory, at its final address for the
            // kernel's life, and its object is held for the value's life. Its plain fields are the
            // ones its open set, which nothing writes while the object lives; what other threads
            // change meanwhile (the lock, the position and the search) sits in cells (see the
            // type's notes).
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
    pub fn reference_by_name(name: &[u16], case_insensitive: bool) -> Option<ObRef> {
        locked(|directory| {
            let id = directory.lookup_name(name, case_insensitive)?;
            directory.reference(id).then(|| ObRef { id })
        })
    }

    /// The token of the process `process` names, referenced: the one it holds, or a new one made
    /// for it, found or made and referenced in one hold of the directory, so the process's end
    /// cannot take it between them. None when the token pool is exhausted.
    pub fn reference_process_token(process: ObjectId) -> Option<ObRef> {
        locked(|directory| {
            let id = directory.process_token(process)?;
            directory.reference(id).then(|| ObRef { id })
        })
    }

    /// The process `process` names lets go of its token, if it holds one (its end, or its
    /// deletion: whichever comes first): the process's reference goes, and the token with it once
    /// no handle holds it.
    pub fn release_process_token(process: ObjectId) {
        if let Some(token) = locked(|directory| directory.take_process_token(process)) {
            release(token);
        }
    }

    /// Drop a reference on `id` (the last one deletes the object, the caller finishing what the
    /// deletion leaves once the directory is released). A process that never had a thread, or one
    /// reaped, goes once only its own reference is left (see
    /// [`crate::process::threads::delete_if_abandoned`]).
    pub fn release(id: ObjectId) {
        if let Some(followup) = locked(|directory| directory.dereference(id)) {
            finish(followup);
        }
        if id.kind == ObjectType::Process {
            crate::process::threads::delete_if_abandoned(id);
        }
    }

    /// A view went: drop its reference on what it mapped (the last one deletes it, the caller
    /// finishing what the deletion leaves).
    pub fn release_mapping(mapping: Mapping) {
        if let Some(followup) = locked(|directory| directory.release_mapping(mapping)) {
            finish(followup);
        }
    }

    /// Publish a new object: a handle to it in `process` (the current one) granted `access`
    /// (its generic rights mapped: [`ObjectType::granted`], checked against the object's
    /// security descriptor and the caller's token when the caller is in user mode:
    /// [`security::grant_handle`]) and `inheritance`, and its creator's reference dropped — the
    /// handle holds it from now on. A failure (the table is full, or the access check denied the
    /// grant) takes the object back with it.
    pub fn publish(
        process: &crate::process::Process,
        id: ObjectId,
        access: u32,
        inherit: bool,
    ) -> Option<NonZeroU32> {
        let granted = security::grant_handle(process, id, access, true);
        // The create's captured descriptor went onto the object at its allocation; one left over
        // (an OBJ_OPENIF create that found the name bound made no object) is dropped.
        security::take_pending();
        let granted = granted.ok()?;
        let handle = process.insert_object(id, granted, inherit);
        release(id);
        handle
    }

    /// Open the object `id` names as a new handle in `process`, granted `access` (its generic
    /// rights mapped: [`ObjectType::granted`], checked against the object's security descriptor
    /// and the caller's token when the caller is in user mode: [`security::grant_handle`]); none
    /// when the table is full, the object is gone, or the access check denied the grant.
    pub fn open(
        process: &crate::process::Process,
        id: ObjectId,
        access: u32,
        inherit: bool,
    ) -> Option<NonZeroU32> {
        let granted = security::grant_handle(process, id, access, false);
        // An open's OBJECT_ATTRIBUTES descriptor is not stored on the existing object.
        security::take_pending();
        let granted = granted.ok()?;
        process.insert_object(id, granted, inherit)
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

    /// Wait on `objects`, dispatcher objects and file objects, for the running thread: each is
    /// referenced for the wait's whole life — replays after an APC included — and released when
    /// `wait` returns. A thread that ends inside the wait releases the wait's references on its way
    /// out ([`Directory::end_thread_references`]); a file object's second one stays (a wait on a
    /// file is a user-mode one, which a termination ends: the thread leaves it before its exit).
    /// None, with nothing waited on, when one of the objects is gone already (a handle another
    /// thread closed meanwhile).
    pub fn waiting<R>(objects: &[ObjectId], wait: impl FnOnce() -> R) -> Option<R> {
        let index = current_thread()
            .expect("a service runs on a pooled thread")
            .index;
        // A file object's deletion leaves its close to finish outside the directory: a reference of
        // the call's own on each, taken with the wait's and dropped after them, is the one that may
        // be its last.
        let files = || objects.iter().filter(|id| id.kind == ObjectType::File);
        let held = locked(|directory| {
            if !directory.hold_wait(index, objects) {
                return false;
            }
            // The wait's reference is held: the call's is a holder's.
            for &id in files() {
                directory.reference_held(id);
            }
            true
        });
        if !held {
            return None;
        }
        let result = wait();
        locked(|directory| directory.release_wait(index));
        for &id in files() {
            release(id);
        }
        // A process that never had a thread, or one reaped, goes with the last reference beside
        // its own, a wait's included.
        for &id in objects {
            if id.kind == ObjectType::Process {
                crate::process::threads::delete_if_abandoned(id);
            }
        }
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

    /// `text`'s UTF-16 units: a name as a UNICODE_STRING gives it.
    fn w(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    thread_local! {
        /// The pages this test thread's slot pools grow from.
        static PAGES: core::cell::Cell<&'static crate::slots::HostPages> =
            core::cell::Cell::new(&crate::slots::KERNEL_PAGES);
    }

    /// The pages the directory's slot pools grow from, on this test thread.
    pub(super) fn pages() -> &'static crate::slots::HostPages {
        PAGES.with(core::cell::Cell::get)
    }

    /// From now on, this thread's slot pools grow from `budget` pages only: a pool past its made
    /// chunks then refuses as when the nonpaged pool is spent.
    fn page_budget(budget: usize) {
        let pages = Box::leak(Box::new(crate::slots::HostPages::with_budget(budget)));
        PAGES.with(|cell| cell.set(pages));
    }

    /// Everything `make` makes until its first refusal.
    fn until_refused<T>(mut make: impl FnMut() -> Option<T>) -> Vec<T> {
        core::iter::from_fn(|| make()).collect()
    }

    fn directory() -> &'static mut Directory {
        crate::sched::testkit::dispatcher();
        let mut directory = Box::<Directory>::new_uninit();
        // SAFETY: the box is valid, aligned and the records' final address once leaked.
        unsafe { Directory::write_empty(directory.as_mut_ptr()) };
        // SAFETY: written whole just above.
        Box::leak(unsafe { directory.assume_init() })
    }

    /// The dispatcher of the newest directory.
    fn dispatcher() -> crate::sched::testkit::Disp {
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
        directory.bind_name(&w("F2K.sync.semaphore"), id).unwrap();
        assert_eq!(
            directory.lookup_name(&w("F2K.sync.semaphore"), false),
            Some(id)
        );
        assert_eq!(
            directory.lookup_name(&w("f2k.sync.semaphore"), false),
            None,
            "case-sensitive"
        );
        assert_eq!(directory.lookup_name(&w("F2K.sync"), false), None);
        assert!(directory.reference(id));
        assert_eq!(closed(directory, id), vec![]);
        assert!(directory.is_live(id));
        assert_eq!(
            directory.lookup_name(&w("F2K.sync.semaphore"), false),
            None,
            "the last handle took the name"
        );
        // The name is free for another object.
        let other = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        directory
            .bind_name(&w("F2K.sync.semaphore"), other)
            .unwrap();
        assert_eq!(
            directory.lookup_name(&w("F2K.sync.semaphore"), false),
            Some(other)
        );
    }

    /// A name is any UTF-16 units: a CJK name, one with a surrogate pair, and a lone surrogate each
    /// bind and look up as given, kept apart from the names they would collapse to in a code page.
    #[test]
    fn a_name_is_any_utf16_units() {
        let directory = directory();
        let cjk = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let pair = directory.create_mutex().unwrap();
        let lone = directory.create_semaphore(0, 1).unwrap();
        directory.bind_name(&w("\u{4E8B}\u{4EF6}"), cjk).unwrap();
        directory.bind_name(&w("F2K.\u{1F600}"), pair).unwrap();
        directory.bind_name(&[0x41, 0xD800, 0x42], lone).unwrap();
        assert_eq!(
            directory.lookup_name(&w("\u{4E8B}\u{4EF6}"), false),
            Some(cjk)
        );
        assert_eq!(
            directory.lookup_name(&w("\u{4E8B}\u{4EF6}"), true),
            Some(cjk)
        );
        assert_eq!(
            directory.lookup_name(&w("F2K.\u{1F600}"), false),
            Some(pair)
        );
        assert_eq!(
            directory.lookup_name(&[0x41, 0xD800, 0x42], false),
            Some(lone)
        );
        assert_eq!(directory.lookup_name(&w("??"), false), None, "no best fit");
        assert_eq!(directory.lookup_name(&w("\u{4E8B}"), false), None);
        assert_eq!(
            directory.name_of(cjk),
            Some(&w("\u{4E8B}\u{4EF6}")[..]),
            "the units as given"
        );
        assert_eq!(directory.name_of(pair), Some(&w("F2K.\u{1F600}")[..]));
    }

    /// OBJ_CASE_INSENSITIVE folds the comparison as the kernel's upcase table does (ASCII and
    /// Latin-1 letters; other units compare as they are); without it a name compares exactly.
    #[test]
    fn a_case_insensitive_lookup_folds() {
        let directory = directory();
        let id = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        directory.bind_name(&w("Caf\u{E9}.\u{4E8B}"), id).unwrap();
        assert_eq!(
            directory.lookup_name(&w("CAF\u{C9}.\u{4E8B}"), true),
            Some(id)
        );
        assert_eq!(
            directory.lookup_name(&w("caf\u{e9}.\u{4E8B}"), true),
            Some(id)
        );
        assert_eq!(directory.lookup_name(&w("CAF\u{C9}.\u{4E8B}"), false), None);
        assert_eq!(
            directory.lookup_name(&w("Caf\u{E9}.\u{4E8B}"), false),
            Some(id)
        );
        assert_eq!(directory.lookup_name(&w("Cafe.\u{4E8B}"), true), None);
        assert_eq!(
            directory.lookup_name(&w("Local\\CAF\u{C9}.\u{4E8B}"), true),
            Some(id),
            "past the session prefix"
        );
    }

    /// The name table refuses an over-long name, grows past the 256 names it once held, and
    /// refuses a name only when no page is left for it.
    #[test]
    fn the_name_table_bounds() {
        let directory = directory();
        let id = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        assert_eq!(
            directory.bind_name(&[u16::from(b'x'); MAX_NAME + 1], id),
            Err(NameError::TooLong)
        );
        for index in 0..1000 {
            directory.bind_name(&w(&format!("n{index}")), id).unwrap();
        }
        for index in 0..1000 {
            assert_eq!(
                directory.lookup_name(&w(&format!("n{index}")), false),
                Some(id)
            );
        }
        page_budget(0);
        let more = until_refused(|| directory.bind_name(&w("more"), id).ok());
        assert!(
            more.len() < per_page::<NameEntry>(),
            "the made chunk's rest"
        );
        assert_eq!(
            directory.bind_name(&w("one more"), id),
            Err(NameError::Full)
        );
    }

    /// A full name table refuses the next name, and the names an object's deletion frees serve the
    /// next binds.
    #[test]
    fn the_name_table_fills_and_reuses() {
        let directory = directory();
        let first = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let second = directory.create_mutex().unwrap();
        for index in 0..300 {
            directory
                .bind_name(&w(&format!("n{index}")), first)
                .unwrap();
        }
        page_budget(0);
        until_refused(|| directory.bind_name(&w("n"), first).ok());
        assert_eq!(
            directory.bind_name(&w("second"), second),
            Err(NameError::Full)
        );
        // One name's room, for the second object.
        let freed = directory.names.iter().next().map(|(name, _)| name).unwrap();
        assert!(directory.names.free(freed));
        directory.bind_name(&w("second"), second).unwrap();
        assert_eq!(
            directory.bind_name(&w("refused"), second),
            Err(NameError::Full)
        );
        assert_eq!(
            directory.lookup_name(&w("refused"), false),
            None,
            "nothing bound"
        );

        assert_eq!(directory.dereference(second), None);
        assert_eq!(
            directory.lookup_name(&w("second"), false),
            None,
            "its name went with it"
        );
        let third = directory.create_semaphore(0, 1).unwrap();
        directory.bind_name(&w("third"), third).unwrap();
        assert_eq!(directory.lookup_name(&w("third"), false), Some(third));
        assert_eq!(
            directory.bind_name(&w("refused"), third),
            Err(NameError::Full)
        );
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
        let mut dispatcher = dispatcher();
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
        let mut dispatcher = dispatcher();
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
        for kind in [
            ObjectType::Section,
            ObjectType::File,
            ObjectType::Key,
            ObjectType::Token,
        ] {
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
            let thread = directory.renew_thread(id);
            let mut dispatcher = dispatcher();
            let record = dispatcher.thread_mut(thread);
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

    /// The timer table fills at its capacity — a create is refused, nothing made — and a deleted
    /// timer's record serves the next create, disarmed and unsignaled.
    #[test]
    fn the_timer_table_fills_and_reuses() {
        let directory = directory();
        let mut dispatcher = dispatcher();
        let timers: Vec<_> = (0..TIMERS)
            .map(|_| directory.create_timer(true).unwrap())
            .collect();
        assert_eq!(directory.create_timer(false), None, "the table is full");
        assert_eq!(directory.live_objects(), TIMERS, "the refusal made nothing");

        let freed = timers[TIMERS / 2];
        dispatcher.set_waitable_timer(directory.timer(freed).unwrap(), 1_000_000, 0, 0, false, 0);
        assert_eq!(directory.dereference(freed), None);
        let reused = directory.create_timer(false).unwrap();
        assert_eq!(reused.index, freed.index, "the freed record is reused");
        assert!(directory.timer(freed).is_none(), "under a new generation");
        assert!(!dispatcher.waitable_timer_mut(reused.index).armed());
        assert_eq!(directory.create_timer(true), None, "full again");
    }

    /// The process table fills at its capacity — a create is refused, nothing made — and a process
    /// object whose creator's reference was its only one goes with it (a create whose record the
    /// pool could not make undoes so), its record serving the next create.
    #[test]
    fn the_process_table_fills_and_reuses() {
        let directory = directory();
        let processes: Vec<_> = (0..PROCESSES)
            .map(|_| directory.create_process().unwrap())
            .collect();
        assert_eq!(directory.create_process(), None, "the table is full");
        assert_eq!(
            directory.live_objects(),
            PROCESSES,
            "the refusal made nothing"
        );

        let undone = processes[PROCESSES - 1];
        assert_eq!(directory.dereference(undone), None, "nothing to finish");
        assert!(!directory.is_live(undone));
        let reused = directory.create_process().unwrap();
        assert_eq!(reused.index, undone.index, "the freed record is reused");
        assert_ne!(reused.generation, undone.generation);
        assert_eq!(directory.create_process(), None, "full again");
    }

    /// The section table grows past the 128 it once held, refuses a create only when no page is
    /// left for it — nothing made — and a deleted section's record serves the next create.
    #[test]
    fn the_section_table_fills_and_reuses() {
        let directory = directory();
        let mut sections: Vec<_> = (0..300)
            .map(|_| directory.create_section(SectionObject::none()).unwrap())
            .collect();
        page_budget(0);
        sections.extend(until_refused(|| {
            directory.create_section(SectionObject::none())
        }));
        assert_eq!(directory.create_section(SectionObject::none()), None);
        assert_eq!(
            directory.live_objects(),
            sections.len(),
            "the refusal made nothing"
        );

        let freed = sections[150];
        assert!(directory.dereference(freed).is_some(), "its frames go back");
        let reused = directory.create_section(SectionObject::none()).unwrap();
        assert_eq!(reused.index, freed.index, "the freed record is reused");
        assert!(directory.section(freed).is_none(), "under a new generation");
        assert_eq!(directory.create_section(SectionObject::none()), None);
    }

    /// Past the image cache's bound, a cached segment gives its record up to the next, the least
    /// recently cached first; an active one never does.
    #[test]
    fn the_segment_table_fills_and_reuses() {
        let directory = directory();
        let segment = |index: u16| {
            ImageSegment::new(
                ObjectId {
                    kind: ObjectType::File,
                    index,
                    generation: 0,
                },
                0x1000_0000,
                0x3000,
            )
        };
        let segments: Vec<_> = (0..SEGMENTS as u16)
            .map(|index| directory.create_segment(segment(index)).unwrap())
            .collect();
        assert_eq!(directory.segments.live() as usize, SEGMENTS);

        assert_eq!(
            directory.make_room_for_segment(),
            None,
            "an active segment is never evicted"
        );

        // Two segments are cached, the later one first.
        let (older, newer) = (segments[SEGMENTS / 2], segments[3]);
        assert_eq!(
            directory.dereference_segment(older),
            Some(Followup::Park(older))
        );
        assert_eq!(
            directory.dereference_segment(newer),
            Some(Followup::Park(newer))
        );
        assert!(directory.segment_cached(older) && directory.segment_cached(newer));
        // Room is made from the least recently cached.
        let evicted = directory.make_room_for_segment();
        assert_eq!(
            evicted,
            Some(Followup::Section {
                frames: crate::mem::vm::SectionFrames::empty(),
                file_object: Some(segment(SEGMENTS as u16 / 2).file_object),
                parked: None,
            }),
            "its file goes back"
        );
        assert!(directory.segment(older).is_none(), "its id is stale");
        let reused = directory.create_segment(segment(0)).unwrap();
        assert_eq!(reused.index, older.index, "the evicted record is reused");
        assert!(directory.segment_cached(newer), "the newer stays cached");
        assert_eq!(
            directory.make_room_for_segment().map(|_| ()),
            Some(()),
            "then it goes"
        );
        assert!(directory.segment(newer).is_none());
        assert_eq!(
            directory.make_room_for_segment(),
            None,
            "room, so nothing goes"
        );
    }

    /// While every segment is active, a new one is made past the image cache's bound all the
    /// same (the table grows); once one is cached, it is the one room is made from, and only a
    /// pool with no page left refuses a segment.
    #[test]
    fn the_segment_table_grows_past_the_cache_bound() {
        let directory = directory();
        let segment = |index: u16| {
            ImageSegment::new(
                ObjectId {
                    kind: ObjectType::File,
                    index,
                    generation: 1,
                },
                0x1000_0000,
                0x1000,
            )
        };
        let segments: Vec<_> = (0..SEGMENTS as u16 + 40)
            .map(|index| {
                assert_eq!(directory.make_room_for_segment(), None, "all active");
                directory.create_segment(segment(index)).unwrap()
            })
            .collect();
        assert_eq!(directory.segments.live() as usize, SEGMENTS + 40);
        let cached = segments[7];
        assert_eq!(
            directory.dereference_segment(cached),
            Some(Followup::Park(cached))
        );
        assert!(directory.make_room_for_segment().is_some());
        assert!(directory.segment(cached).is_none(), "the cached one went");
        assert_eq!(directory.make_room_for_segment(), None, "all active again");
        page_budget(0);
        let more = until_refused(|| directory.create_segment(segment(0)));
        assert!(directory.create_segment(segment(0)).is_none(), "no page");
        assert_eq!(
            directory.segments.live() as usize,
            SEGMENTS + 39 + more.len()
        );
    }

    /// The file-object table grows past the 512 it once held, refuses an open only when no page is
    /// left for it — nothing made — and a file object's close frees its record for the next open.
    #[test]
    fn the_file_object_table_fills_and_reuses() {
        use crate::fs::file::{Context, FileRecordId, ACCESS_READ, SHARE_ALL};
        let directory = directory();
        let open = |directory: &mut Directory, record: u16| {
            directory.create_file(
                Context::Disk(FileRecordId::at(record)),
                ACCESS_READ,
                0,
                SHARE_ALL,
            )
        };
        let mut files: Vec<_> = (0..600)
            .map(|record| open(directory, record).unwrap())
            .collect();
        page_budget(0);
        files.extend(until_refused(|| open(directory, 0)));
        assert_eq!(open(directory, 0), None, "the table is full");
        assert_eq!(
            directory.live_objects(),
            files.len(),
            "the refusal made nothing"
        );

        let freed = files[300];
        published(directory, freed);
        assert_eq!(
            closed(directory, freed).len(),
            2,
            "its cleanup, then its close"
        );
        let reused = open(directory, 0).unwrap();
        assert_eq!(reused.index, freed.index, "the freed record is reused");
        assert!(directory.file(freed).is_none(), "under a new generation");
        assert_eq!(open(directory, 1), None, "full again");
    }

    /// Every kind on a slot pool: a new object's generation is 1, never 0; an id never handed out
    /// (generation 0, or an index past every made record) names nothing; the deletion makes the
    /// id stale at once, and the record serves the kind's next create under the next generation.
    #[test]
    fn slot_kinds_name_only_their_live_objects() {
        use crate::fs::file::{Context, FileRecordId};
        let directory = directory();
        let makers: [fn(&mut Directory) -> Option<ObjectId>; 10] = [
            |d| d.create_section(SectionObject::none()),
            |d| d.create_file(Context::Disk(FileRecordId::at(1)), 0, 0, 0),
            |d| d.create_window_station("W", 0),
            |d| d.create_desktop("D", 0),
            |d| d.create_key(crate::cm::KeyBody::none()),
            |d| d.create_dc(crate::win32k::dc::Dc::none()),
            |d| d.create_brush(crate::win32k::brush::Brush::none()),
            |d| d.create_bitmap(crate::win32k::bitmap::Bitmap::none()),
            |d| d.create_font(crate::win32k::fonts::FontObject::none()),
            |d| d.create_token(crate::se::TokenBody::none()),
        ];
        for make in makers {
            let first = make(directory).unwrap();
            assert_eq!(first.generation, 1, "{:?}'s first", first.kind);
            assert!(directory.is_live(first));
            let never = [
                ObjectId {
                    generation: 0,
                    ..first
                },
                ObjectId {
                    generation: 2,
                    ..first
                },
                ObjectId {
                    index: first.index + 5000,
                    ..first
                },
            ];
            for id in never {
                assert!(!directory.reference(id), "{id:?} was never handed out");
                assert_eq!(directory.counts(id), None);
            }
            let _ = directory.dereference(first);
            assert!(!directory.is_live(first), "{:?}'s id is stale", first.kind);
            assert!(!directory.reference(first));
            let second = make(directory).unwrap();
            assert_eq!(
                second.index, first.index,
                "{:?}'s record reused",
                first.kind
            );
            assert_eq!(second.generation, 2);
            assert!(!directory.is_live(first));
            let _ = directory.dereference(second);
        }
        assert_eq!(directory.live_objects(), 0);
    }

    /// A deleted mutex its owner still held leaves the owner's list: the owner's end then has
    /// nothing of it to abandon.
    #[test]
    fn a_deleted_owned_mutex_leaves_its_owner() {
        let directory = directory();
        let mut dispatcher = dispatcher();
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
        let other = directory.create_window_station("Other", 0).unwrap();
        assert_ne!(other, station, "another is its own object");
        assert_eq!(directory.dereference(other), None);
        for id in [station, desktop] {
            assert!(directory.handle_opened(id));
            assert_eq!(closed(directory, id), vec![]);
            assert_eq!(directory.counts(id), Some((1, 0)));
        }
        assert_eq!(sweep(directory).0, 0);
        assert!(directory.is_live(station) && directory.is_live(desktop));
    }

    /// A device context, as win32k's services make one: typed, never waited on, its state the
    /// body's; its handle's close deletes it, its id going stale; one a process left behind is a
    /// leak the sweep takes; the pool refuses a DC only when no page is left for it.
    #[test]
    fn a_dc_lives_while_its_handle_does() {
        use crate::win32k::dc::Dc;
        let directory = directory();
        let id = directory.create_dc(Dc::screen(640, 480)).unwrap();
        assert_eq!(id.kind, ObjectType::Dc);
        assert_eq!(directory.waitable(id), None);
        assert_eq!(directory.dc(id).copied(), Some(Dc::screen(640, 480)));
        assert!(directory.key(id).is_none(), "typed");
        published(directory, id);
        directory.dc(id).unwrap().text_color = 0xFF;
        assert_eq!(
            directory.dc(id).unwrap().text_color,
            0xFF,
            "the body holds the state"
        );
        assert_eq!(directory.counts(id), Some((1, 1)));
        assert_eq!(
            closed(directory, id),
            vec![],
            "nothing outside the directory"
        );
        assert!(!directory.is_live(id));
        assert!(directory.dc(id).is_none(), "the id is stale");

        let leaked = directory.create_dc(Dc::screen(640, 480)).unwrap();
        published(directory, leaked);
        assert_eq!(sweep(directory), (1, vec![]), "a DC left behind is a leak");
        assert!(!directory.is_live(leaked));

        let mut made: Vec<_> = (0..100)
            .map(|_| directory.create_dc(Dc::screen(1, 1)).unwrap())
            .collect();
        page_budget(0);
        made.extend(until_refused(|| directory.create_dc(Dc::screen(1, 1))));
        assert_eq!(
            directory.create_dc(Dc::screen(1, 1)),
            None,
            "the pool is full"
        );
        for id in made {
            assert_eq!(directory.dereference(id), None);
        }
    }

    /// The sweep at quiescence deletes whatever outlived its process (a reference leak, reported)
    /// and starts every thread record and name over.
    #[test]
    fn the_sweep_clears_the_directory() {
        let directory = directory();
        let leaked = directory
            .create_event(EventKind::Notification, true)
            .unwrap();
        directory.bind_name(&w("left"), leaked).unwrap();
        let main = directory.create_thread_in(0..1).unwrap();
        record(ThreadId(main.index)).teb_va = 0x7FFD_E000;
        assert_eq!(sweep(directory).0, 2);
        assert_eq!(directory.live_objects(), 0);
        assert!(!directory.is_live(leaked));
        assert_eq!(directory.lookup_name(&w("left"), false), None);
        assert_eq!(
            record(ThreadId(main.index)).teb_va(),
            0,
            "records start over"
        );
    }

    /// The sweep's end starts over the records thread objects were handed since the last one,
    /// and only those: a record no thread had since is as that sweep left it.
    #[test]
    fn the_sweep_renews_the_records_handed_out_since_the_last() {
        let directory = directory();
        let first = directory.create_thread_in(0..1).unwrap();
        record(ThreadId(first.index)).teb_va = 0x7FFD_E000;
        assert_eq!(directory.dereference(first), None);
        // A record no thread object was handed: written here as nothing in the kernel would.
        record(ThreadId(5)).teb_va = 0x7FFD_D000;
        assert_eq!(sweep(directory).0, 0);
        assert_eq!(record(ThreadId(first.index)).teb_va(), 0, "renewed");
        assert_eq!(record(ThreadId(5)).teb_va(), 0x7FFD_D000, "not renewed");

        // The next sweep renews only what was handed out after this one: the first record again,
        // and none other.
        let again = directory.create_thread_in(0..1).unwrap();
        assert_eq!(again.index, first.index);
        record(ThreadId(again.index)).teb_va = 0x7FFD_C000;
        assert_eq!(directory.dereference(again), None);
        let other = directory.create_thread_in(2..3).unwrap();
        record(ThreadId(other.index)).teb_va = 0x7FFD_B000;
        assert_eq!(sweep(directory).0, 1, "the thread object still held");
        assert_eq!(record(ThreadId(again.index)).teb_va(), 0);
        assert_eq!(record(ThreadId(other.index)).teb_va(), 0);
        assert_eq!(record(ThreadId(5)).teb_va(), 0x7FFD_D000);
        assert_eq!(sweep(directory).0, 0);
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
        directory.bind_name(&w("F2K.a"), a_event).unwrap();
        let b_semaphore = directory.create_semaphore(0, 1).unwrap();
        published(directory, b_semaphore);
        directory.bind_name(&w("F2K.b"), b_semaphore).unwrap();
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
        assert_eq!(directory.lookup_name(&w("F2K.a"), false), None);
        for id in [a_main, a_child] {
            let ended = record(ThreadId(id.index));
            assert!(ended.process.is_null() && ended.teb_va() == 0, "reset");
        }
        assert_eq!(directory.counts(b_semaphore), Some((1, 1)), "the other's");
        assert_eq!(directory.lookup_name(&w("F2K.b"), false), Some(b_semaphore));
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
        directory.bind_name(&w("Global\\F2K.ready"), event).unwrap();
        assert_eq!(directory.lookup_name(&w("F2K.ready"), false), Some(event));
        assert_eq!(
            directory.lookup_name(&w("Local\\F2K.ready"), false),
            Some(event)
        );
        assert_eq!(
            directory.lookup_name(&w("Global\\F2K.ready"), false),
            Some(event)
        );
        assert_eq!(
            directory.lookup_name(&w("global\\F2K.ready"), false),
            None,
            "the prefix as spelled"
        );
        // Another kind finds the same binding: its create sees a kind mismatch.
        let found = directory.lookup_name(&w("F2K.ready"), false).unwrap();
        assert_eq!(found.kind, ObjectType::Event);
        assert_eq!(
            namespace_name(&w("Local\\")),
            w(""),
            "a bare prefix names nothing"
        );
        assert_eq!(namespace_name(&w("Session\\1")), w("Session\\1"));
    }

    /// A process object's deletion is claimed while its own reference alone holds it: the moment
    /// a process that never had a thread, or one reaped, is deleted. A handle or another reference
    /// holds it, and no other kind is a process's. The claim takes a reference, so a second claim
    /// finds the object held, until the deletion's end drops both at once.
    #[test]
    fn a_process_objects_deletion_is_claimed_once_its_own_reference_alone_holds_it() {
        let directory = directory();
        let id = directory.create_process().unwrap();
        assert!(directory.handle_opened(id));
        assert!(!directory.claim_deletion(id), "a handle holds it");
        assert!(directory.reference(id));
        assert!(directory.handle_closed(id).iter().next().is_none());
        assert!(!directory.claim_deletion(id), "a reference holds it");
        assert_eq!(directory.dereference(id), None);
        let event = directory.create_event(EventKind::Notification, false);
        assert!(event.is_some_and(|event| !directory.claim_deletion(event)));
        assert!(directory.claim_deletion(id), "its own reference alone");
        assert_eq!(directory.counts(id), Some((2, 0)), "the claim's reference");
        assert!(!directory.claim_deletion(id), "claimed once");
        // The deletion's end drops the process's own reference and the claim's: the object goes.
        directory.end_claimed_deletion(id);
        assert!(
            !directory.is_live(id) && !directory.claim_deletion(id),
            "gone"
        );
    }

    /// A process object: waitable, still active and unsignaled until its end, signaled with its
    /// exit code at the end; the sweep leaves it to its own reference, whose
    /// release frees the record for the next process; the pool's capacity is the process
    /// pool's.
    #[test]
    fn a_process_object_signals_its_end() {
        let directory = directory();
        let mut dispatcher = dispatcher();
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
                parked: None,
            })
        );
        let record = directory.sections.address(id.index.into()).unwrap();
        // SAFETY: a made chunk's record, which nothing changes meanwhile.
        let size = unsafe { record.as_ref() }.body.size;
        assert_eq!(size, 0, "the record holds no mapping any more");
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
            .create_segment(ImageSegment::new(file_object, 0x1000_0000, 0x3000))
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
        // The last view leaves it cached, its frames to park, and a later section revives it.
        assert_eq!(
            directory.release_mapping(view),
            Some(Followup::Park(segment))
        );
        assert!(
            directory.segment_cached(segment),
            "cached, its file's still"
        );
        assert!(directory.reference_segment(segment), "revived");
        assert!(!directory.segment_cached(segment));
        assert_eq!(
            directory.dereference_segment(segment),
            Some(Followup::Park(segment))
        );
        // The file changes: the cached segment is purged, its frames and file given back.
        let gone = Followup::Section {
            frames: crate::mem::vm::SectionFrames::empty(),
            file_object: Some(file_object),
            parked: None,
        };
        assert_eq!(directory.purge_segment(segment), Some(gone));
        assert!(directory.segment(segment).is_none(), "its id is stale");
        assert!(!directory.reference_segment(segment));
        assert_eq!(directory.purge_segment(segment), None);
        assert_eq!(directory.release_mapping(view), None);
        // A section that outlives the views is the last holder in its turn.
        let again = directory
            .create_segment(ImageSegment::new(file_object, 0x1000_0000, 0x3000))
            .unwrap();
        assert_eq!(again.index, segment.index, "the record is reused");
        assert_ne!(again, segment, "under a new generation");
        let section = image_section(directory, again);
        assert!(directory.reference_segment(again), "a view");
        assert_eq!(directory.release_mapping(Mapping::Image(again)), None);
        assert_eq!(closed(directory, section), vec![Followup::Park(again)]);
        // A segment whose file changes while it is active is detached: its last reference deletes
        // it.
        assert!(directory.reference_segment(again), "revived");
        assert_eq!(directory.purge_segment(again), None, "detached");
        assert!(directory.segment(again).is_some(), "still mapped");
        assert_eq!(directory.dereference_segment(again), Some(gone));
        assert!(directory.segment(again).is_none());
        // A data view holds its section, as before.
        let data = directory.create_section(SectionObject::none()).unwrap();
        assert_eq!(
            directory.release_mapping(Mapping::Section(data)),
            Some(Followup::Section {
                frames: crate::mem::vm::SectionFrames::empty(),
                file_object: None,
                parked: None,
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
                .create_segment(ImageSegment::new(
                    ObjectId {
                        kind: ObjectType::File,
                        index,
                        generation: 0,
                    },
                    0x1000_0000,
                    0x1000,
                ))
                .unwrap()
        };
        let held = segment(directory, 1);
        image_section(directory, held);
        segment(directory, 2);
        // A cached segment is no leak: it, and the file object it holds, outlive the sweep.
        let (cached, file) = cached_image(directory, 9);
        assert!(directory.image_cache_settled(|_| true));
        let (leaks, followups) = sweep(directory);
        assert_eq!(leaks, 2, "the section and the lone segment");
        assert_eq!(followups.len(), 2);
        assert!(
            followups
                .iter()
                .all(|followup| matches!(followup, Followup::Section { .. })),
            "the leaked section's segment goes with it, not into the cache"
        );
        assert_eq!(directory.segments.live(), 1, "the cached one");
        assert!(directory.segment_cached(cached));
        assert!(directory.is_live(file), "its file object stays open");
        // Purged (a shutdown), it gives its file object back.
        assert!(directory.purge_next_cached().is_some());
        assert_eq!(directory.purge_next_cached(), None);
    }

    /// A cached image of the file whose record is `record`, as a process's end leaves it: a file
    /// object (its handle closed) held by the segment alone, the segment cached. The segment
    /// and the file object.
    fn cached_image(directory: &mut Directory, record: u16) -> (SegmentId, ObjectId) {
        use crate::fs::file::{Context, FileRecordId};
        let context = Context::Disk(FileRecordId::at(record));
        let file = directory.create_file(context, 1, 0x8000_0000, 1).unwrap();
        let segment = directory
            .create_segment(ImageSegment::new(file, 0x1000_0000, 0x1000))
            .unwrap();
        assert!(directory.reference(file), "the segment's");
        assert_eq!(directory.dereference(file), None, "the open's, gone");
        assert_eq!(
            directory.dereference_segment(segment),
            Some(Followup::Park(segment))
        );
        (segment, file)
    }

    /// The image cache outlives quiescence only while its file objects are its own: one held by
    /// anything else (a leaked reference or handle), or a file record that something else holds,
    /// unsettles it. A cached segment names its file's record.
    #[test]
    fn the_image_cache_settles_when_only_it_holds_its_files() {
        use crate::fs::file::FileRecordId;
        let directory = directory();
        assert!(directory.image_cache_settled(|_| false), "no cache");
        let (_, file) = cached_image(directory, 4);
        assert!(directory.caches_record(FileRecordId::at(4)));
        assert!(!directory.caches_record(FileRecordId::at(5)));
        assert!(
            directory.image_cache_settled(|object| { object.disk() == Some(FileRecordId::at(4)) })
        );
        assert!(
            !directory.image_cache_settled(|_| false),
            "its record held elsewhere"
        );
        assert!(directory.reference(file), "a leaked reference");
        assert!(!directory.image_cache_settled(|_| true));
        assert_eq!(directory.dereference(file), None);
        assert!(directory.handle_opened(file), "a leaked handle");
        assert!(!directory.image_cache_settled(|_| true));
        // The sweep then takes the leak (the cache purged first, as the reap does).
        assert!(directory.purge_next_cached().is_some());
        let (leaks, _) = sweep(directory);
        assert_eq!(leaks, 1, "the file object");
        assert!(!directory.caches_record(FileRecordId::at(4)));
    }

    /// A file object's last handle is its cleanup (share access, delete-on-close), and its last
    /// reference its close: a mapping's reference holds it between the two. It is no waitable.
    #[test]
    fn a_file_object_cleans_up_then_closes() {
        use crate::fs::file::{Context, FileRecordId};
        let directory = directory();
        let four = Context::Disk(FileRecordId::at(4));
        let id = directory
            .create_file(
                four,
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
                object: id,
                context: four,
                access: 1,
                share: 7,
                delete_on_close: true,
            }]
        );
        assert_eq!(
            directory.dereference(id),
            Some(Followup::FileClose { context: four })
        );
        // Both at once when nothing else holds it.
        let five = Context::Disk(FileRecordId::at(5));
        let id = directory.create_file(five, 0, 0x80, 0).unwrap();
        published(directory, id);
        assert_eq!(
            closed(directory, id),
            vec![
                Followup::FileCleanup {
                    object: id,
                    context: five,
                    access: 0,
                    share: 0,
                    delete_on_close: false,
                },
                Followup::FileClose { context: five },
            ]
        );
    }

    /// A process's token is made at the first ask and found again after; its handles keep it
    /// once the process lets go of it, and the last one deletes it. Another process gets a token
    /// of its own.
    #[test]
    fn a_process_token_is_made_once_and_outlives_its_process() {
        let directory = directory();
        let process = |index| ObjectId {
            kind: ObjectType::Process,
            index,
            generation: 0,
        };
        let token = directory.process_token(process(1)).unwrap();
        assert_eq!(token.kind, ObjectType::Token);
        assert_eq!(directory.process_token(process(1)), Some(token));
        assert_ne!(directory.process_token(process(2)), Some(token));
        assert!(directory.handle_opened(token));
        assert_eq!(directory.counts(token), Some((2, 1)));
        assert_eq!(directory.take_process_token(process(1)), Some(token));
        assert_eq!(directory.take_process_token(process(1)), None, "once");
        assert_eq!(directory.dereference(token), None);
        assert!(directory.is_live(token), "its handle holds it");
        assert!(closed(directory, token).is_empty());
        assert!(!directory.is_live(token));
        // A new ask after the process let go makes a new token.
        let again = directory.process_token(process(1)).unwrap();
        assert_ne!(again, token);
    }

    /// A small security descriptor's bytes for the tests: a self-relative header, a present DACL
    /// of one allowed ACE, the owner after it.
    fn test_sd(owner: &[u8], aces: &[Vec<u8>]) -> Vec<u8> {
        use crate::sec::{
            SecurityDescriptor,
            ACCESS_ALLOWED_ACE_TYPE,
            ACL_REVISION2,
            SE_DACL_PRESENT,
            SE_SELF_RELATIVE,
        };
        let mut dacl = vec![ACL_REVISION2, 0];
        let size = (8 + aces.iter().map(|a| a.len()).sum::<usize>()) as u16;
        dacl.extend_from_slice(&size.to_le_bytes());
        dacl.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        dacl.extend_from_slice(&0u16.to_le_bytes());
        for ace in aces {
            dacl.extend_from_slice(ace);
        }
        let mut v = vec![0u8; 20];
        let dacl_off = v.len() as u32;
        v.extend_from_slice(&dacl);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        let owner_off = v.len() as u32;
        v.extend_from_slice(owner);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        let h = SecurityDescriptor {
            revision: 1,
            sbz1: 0,
            control: SE_SELF_RELATIVE | SE_DACL_PRESENT,
            owner: owner_off,
            group: 0,
            sacl: 0,
            dacl: dacl_off,
        };
        assert!(h.write(&mut v[..]));
        v
    }

    /// An allowed ACE of `mask` to the SID's bytes `sid`.
    fn allowed_ace(mask: u32, sid: &[u8]) -> Vec<u8> {
        use crate::sec::ACCESS_ALLOWED_ACE_TYPE;
        let size = (4 + 4 + sid.len() + 3) & !3;
        let mut v = vec![ACCESS_ALLOWED_ACE_TYPE, 0];
        v.extend_from_slice(&(size as u16).to_le_bytes());
        v.extend_from_slice(&mask.to_le_bytes());
        v.extend_from_slice(sid);
        v.resize(size, 0);
        v
    }

    /// The test user's SID's bytes.
    fn user_sid() -> Vec<u8> {
        let mut v = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 111, 222, 333, 1000] {
            v.extend_from_slice(&sub.to_le_bytes());
        }
        v
    }

    /// An object carries its security descriptor on its record: the default NULL DACL until a
    /// create's captured one (or a set) replaces it, read back per object, two objects holding
    /// different ones, a dead id naming none.
    #[test]
    fn an_object_carries_its_security_descriptor() {
        let directory = directory();
        let a = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let b = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        // The default: a NULL DACL, present with a zero field.
        assert_eq!(
            directory.security_descriptor(a),
            Some(security::Sd::NULL_DACL.as_slice())
        );
        assert_eq!(
            directory.security_descriptor(b),
            Some(security::Sd::NULL_DACL.as_slice())
        );
        assert_eq!(directory.sd(a).copied(), Some(security::Sd::NULL_DACL));

        // A set replaces it, on that object alone.
        let sd = test_sd(&user_sid(), &[allowed_ace(0x7, &user_sid())]);
        directory.set_security_descriptor(a, &sd).unwrap();
        assert_eq!(directory.security_descriptor(a), Some(&sd[..]));
        assert_eq!(
            directory.security_descriptor(b),
            Some(security::Sd::NULL_DACL.as_slice()),
            "the other object keeps its own"
        );
        // Set again: replaced.
        let other = test_sd(&user_sid(), &[]);
        directory.set_security_descriptor(a, &other).unwrap();
        assert_eq!(directory.security_descriptor(a), Some(&other[..]));

        // The refusals: an empty descriptor, one past the record's storage, a dead id.
        assert_eq!(
            directory.set_security_descriptor(b, &[]),
            Err(crate::status::STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            directory.set_security_descriptor(b, &[0u8; security::MAX_SD + 1]),
            Err(crate::status::STATUS_BUFFER_TOO_SMALL)
        );
        assert!(directory.set_sd(b, security::Sd::NULL_DACL));
        assert_eq!(directory.dereference(a), None);
        assert_eq!(
            directory.security_descriptor(a),
            None,
            "a dead id names none"
        );
        assert_eq!(
            directory.set_security_descriptor(a, &sd),
            Err(crate::status::STATUS_INVALID_HANDLE)
        );
    }

    /// A create's captured (pending) descriptor lands on the object its allocation made; with
    /// none captured, the default goes on.
    #[test]
    fn a_pending_sd_lands_on_the_next_allocated_object() {
        let directory = directory();
        let sd = test_sd(&user_sid(), &[allowed_ace(0x7, &user_sid())]);
        security::set_pending(security::Sd::from_bytes(&sd));
        let id = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        assert_eq!(directory.security_descriptor(id), Some(&sd[..]));
        assert_eq!(security::take_pending(), None, "the allocation took it");

        // A slot-pool kind too, and the kind's default when nothing is pending.
        security::set_pending(security::Sd::from_bytes(&sd));
        let section = directory.create_section(SectionObject::none()).unwrap();
        assert_eq!(directory.security_descriptor(section), Some(&sd[..]));
        let file = directory
            .create_file(crate::fs::file::Context::Null, 0, 0, 0)
            .unwrap();
        assert_eq!(
            directory.security_descriptor(file),
            Some(security::default_sd(ObjectType::File).as_slice())
        );
        let process = directory.create_process().unwrap();
        assert_eq!(
            directory.security_descriptor(process),
            Some(security::default_sd(ObjectType::Process).as_slice())
        );
        let event = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        assert_eq!(
            directory.security_descriptor(event),
            Some(security::Sd::NULL_DACL.as_slice()),
            "the dispatcher kinds keep the NULL DACL"
        );
    }

    /// A handle's grant checks the object's own descriptor: two events, one with a deny-all DACL,
    /// one default, grant differently to the same subject.
    #[test]
    fn a_handle_grant_checks_the_objects_own_sd() {
        use crate::sec::CallerMode;
        let directory = directory();
        let open = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let locked = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let deny_all = test_sd(
            &user_sid(),
            &[{
                use crate::sec::ACCESS_DENIED_ACE_TYPE;
                let mut v = vec![ACCESS_DENIED_ACE_TYPE, 0];
                let size = (4 + 4 + user_sid().len() + 3) & !3;
                v.extend_from_slice(&(size as u16).to_le_bytes());
                v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
                v.extend_from_slice(&user_sid());
                v.resize(size, 0);
                v
            }],
        );
        directory
            .set_security_descriptor(locked, &deny_all)
            .unwrap();

        let token = crate::se::TokenBody::of(ObjectId {
            kind: ObjectType::Process,
            index: 1,
            generation: 0,
        });
        let parts = security::subject_parts(&token);
        let event = ObjectType::Event;
        use rtl::nt::access::GENERIC_ALL;
        assert_eq!(
            security::check_with(
                &parts,
                event,
                GENERIC_ALL,
                directory.security_descriptor(open).unwrap(),
                CallerMode::User
            ),
            Ok(event.granted(GENERIC_ALL)),
            "the default NULL DACL grants all"
        );
        assert_eq!(
            security::check_with(
                &parts,
                event,
                GENERIC_ALL,
                directory.security_descriptor(locked).unwrap(),
                CallerMode::User
            ),
            Err(crate::status::STATUS_ACCESS_DENIED)
        );
        // Kernel mode bypasses the descriptor.
        assert_eq!(
            security::check_with(
                &parts,
                event,
                GENERIC_ALL,
                directory.security_descriptor(locked).unwrap(),
                CallerMode::Kernel
            ),
            Ok(event.granted(GENERIC_ALL))
        );
    }

    // --- The counts' protocol (see `Counts`) --------------------------------------------------

    /// Holders on several processors take and drop references while look-ups try to take theirs:
    /// exactly one release is the last, and once it is, no look-up takes the object back.
    #[test]
    fn the_last_release_is_seen_once_across_processors() {
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        let rounds = if cfg!(miri) { 2 } else { 200 };
        let turns = if cfg!(miri) { 4 } else { 50 };
        const HOLDERS: u32 = 4;
        for _ in 0..rounds {
            let counts = Counts::new(HOLDERS, 0);
            let lasts = AtomicUsize::new(0);
            let dead = AtomicBool::new(false);
            let (counts, lasts, dead) = (&counts, &lasts, &dead);
            let release = move || {
                if counts.release() {
                    assert!(!dead.swap(true, Ordering::Relaxed), "one last release");
                    lasts.fetch_add(1, Ordering::Relaxed);
                }
            };
            std::thread::scope(|scope| {
                for _ in 0..HOLDERS {
                    scope.spawn(move || {
                        for _ in 0..turns {
                            counts.add_held();
                            release();
                        }
                        release();
                    });
                }
                for _ in 0..2 {
                    scope.spawn(move || {
                        for _ in 0..turns {
                            if counts.try_add() {
                                assert!(!dead.load(Ordering::Relaxed), "a dying object revived");
                                release();
                            } else {
                                assert!(counts.unreferenced(), "refused only once dying");
                            }
                        }
                    });
                }
            });
            assert_eq!(lasts.load(Ordering::Relaxed), 1);
            assert!(dead.load(Ordering::Relaxed));
            assert!(!counts.try_add(), "a dying object stays dying");
            assert_eq!(counts.snapshot(), (0, 0));
        }
    }

    /// Between an object's last release and its deletion under the lock, the object is dying: no
    /// look-up finds it, by id, by name or for a handle, and its deletion then runs as it would
    /// have in one hold, its name going with it.
    #[test]
    fn a_dying_object_is_gone_to_every_look_up() {
        let directory = directory();
        let id = directory.create_semaphore(0, 1).unwrap();
        directory.bind_name(&w("F2K.dying"), id).unwrap();
        assert!(directory.reference(id));
        assert_eq!(directory.dereference(id), None, "not the last");

        // The first phase, as a release outside the lock would run it.
        assert!(directory.header(id).unwrap().release(), "the last");
        assert!(!directory.is_live(id));
        assert!(!directory.reference(id), "no look-up by id");
        assert!(!directory.handle_opened(id), "no handle");
        assert_eq!(
            directory.lookup_name(&w("F2K.dying"), false),
            None,
            "no name"
        );
        assert_eq!(directory.counts(id), Some((0, 0)), "nothing counted");

        // The second phase, under the lock: the re-check holds, the object goes.
        assert_eq!(directory.delete_unreferenced(id), None, "nothing to finish");
        assert_eq!(directory.counts(id), None);
        assert_eq!(directory.name_of(id), None, "its name went with it");
        let next = directory.create_semaphore(0, 1).unwrap();
        directory.bind_name(&w("F2K.dying"), next).unwrap();
        assert_eq!(directory.lookup_name(&w("F2K.dying"), false), Some(next));
    }

    /// A second phase that comes after the object's deletion (or after its record went to a new
    /// object) finds its id stale and leaves the record's new object alone.
    #[test]
    fn a_late_second_phase_finds_the_object_gone() {
        let directory = directory();
        let id = directory.create_section(SectionObject::none()).unwrap();
        assert!(directory.header(id).unwrap().release());
        assert!(
            directory.delete_unreferenced(id).is_some(),
            "the section's frames"
        );
        let reused = directory.create_section(SectionObject::none()).unwrap();
        assert_eq!(reused.index, id.index, "the record went to a new object");
        assert_eq!(directory.delete_unreferenced(id), None, "a stale id");
        assert_eq!(directory.counts(reused), Some((1, 0)), "untouched");
    }

    /// An image segment's last reference caches it; a look-up may take it back from the cache
    /// between the release and the second phase, which then leaves it active: neither cached nor
    /// deleted. Its next last release caches it.
    #[test]
    fn a_segment_taken_back_before_the_second_phase_stays_active() {
        let directory = directory();
        let file = ObjectId {
            kind: ObjectType::File,
            index: 0,
            generation: 1,
        };
        let id = directory
            .create_segment(ImageSegment::new(file, 0x1000_0000, 0x1000))
            .unwrap();
        assert!(directory.segment_header(id).unwrap().release());
        assert!(directory.reference_segment(id), "taken back");
        assert_eq!(directory.segment_unreferenced(id), None);
        assert!(!directory.segment_cached(id), "active");
        assert_eq!(directory.dereference_segment(id), Some(Followup::Park(id)));
        assert!(directory.segment_cached(id));
    }

    /// A holder's reference needs no look-up: it counts like any other, and the holder's release
    /// is not the last.
    #[test]
    fn a_holder_adds_a_reference_without_a_look_up() {
        let directory = directory();
        let id = directory.create_mutex().unwrap();
        directory.reference_held(id);
        assert_eq!(directory.counts(id), Some((2, 0)));
        assert_eq!(directory.dereference(id), None);
        assert_eq!(directory.dereference(id), None);
        assert_eq!(directory.counts(id), None, "the last one deleted it");
    }
}
