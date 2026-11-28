//! The directory's records: an object's counts, descriptor and body in its kind's slot pool,
//! the pools' codecs, and the creates that allocate them.

use sdcache::SdRef;

use super::*;
use crate::level::Dispatch;
use crate::sched::dispatcher::Dispatcher;
use crate::slots::{Codec, Id, KernelId, Match, Record, Reuse, Slots};

/// Run `f` on the dispatcher database, where the dispatcher objects' bodies live: the kernel's one
/// dispatcher (on the host, the test thread's). The directory holds no token: it raises to the
/// dispatch level for the length of `f` (the level bridge), so it is never reached from there.
pub(super) fn with_bodies<R>(f: impl FnOnce(&mut Dispatcher) -> R) -> R {
    crate::level::raised::<Dispatch, _>(|dispatch| f(crate::sched::DISPATCHER.get(dispatch)))
}

/// Make the kernel's other records of the thread at object `index`, beside the directory's and the
/// dispatcher's: its stand-in for drivers (an ETHREAD's place) and its pending-descriptor slot.
/// False when no page is left for one; what was made stays, for the next thread at the index.
#[cfg(target_arch = "x86")]
pub(super) fn make_thread_extras(index: u16) -> bool {
    crate::dev::io::make_thread_stand_in(index) && security::make_pending_slot(index)
}

/// The host builds have neither (the descriptor's pending slot is per test thread there).
#[cfg(not(target_arch = "x86"))]
pub(super) fn make_thread_extras(_: u16) -> bool {
    true
}

/// An object's record in its kind's slot pool: its counts, its security descriptor, and its body.
/// The pool's slot holds the liveness and the generation (the slot's uniqueness count: 1 first,
/// moved on at the delete, never 0), and its chunk keeps the record at its address for the
/// kernel's life (a file object's lock event is named by its address).
pub struct ObRecord<B> {
    pub(super) counts: Counts,
    /// The object's security descriptor, as a shared cache handle (see [`sdcache`]); none on a
    /// fresh record.
    pub(super) sd: SdRef,
    pub(super) body: B,
}

/// A kind's slot pool: a page of records at a time, from the nonpaged pool, made as the kind
/// needs them and kept at its peak. Its only bound is the u16 index (65,535 objects of the kind),
/// a representation limit memory reaches first; a create that finds no page fails as a full pool
/// did (STATUS_INSUFFICIENT_RESOURCES).
pub(super) type ObSlots<B, const PER: usize> = Slots<ObRecord<B>, KernelId<B>, PER>;

/// The ob id of the slot `id` of a pool of `kind`.
pub(super) fn object_id<B>(kind: ObjectType, id: Id<B>) -> ObjectId {
    ObjectId {
        kind,
        index: id.index,
        generation: id.uniq,
    }
}

/// The slot id an ob id names in its kind's pool.
pub(super) fn slot_id<B>(id: ObjectId) -> Id<B> {
    Id::new(id.index, id.generation)
}

/// The slot id a segment id names in the segments' pool.
pub(super) fn segment_slot(id: SegmentId) -> Id<ImageSegment> {
    Id::new(id.index, id.generation)
}

/// The pages the slot pools grow from: the kernel's ([`crate::slots::KERNEL_PAGES`]), or a
/// test's own.
#[cfg(not(test))]
pub(super) fn pages() -> &'static impl crate::slots::Pages {
    &crate::slots::KERNEL_PAGES
}

#[cfg(test)]
pub(super) fn pages() -> &'static crate::slots::HostPages {
    super::testkit::pages()
}

/// A new object's record in `pool`, holding its creator's reference: its id and its record, for
/// the caller to fill. The record carries the security descriptor the current create captured
/// (the kind's default when it captured none), as a shared cache handle. None when no page is
/// left for the pool to grow (or its u16 index is spent), or the cache has no room for the
/// descriptor's entry.
pub(super) fn allocate_record<B, C: Codec<Id = Id<B>>, const PER: usize>(
    pool: &mut Slots<ObRecord<B>, C, PER>,
    kind: ObjectType,
    fallback: Option<SdRef>,
) -> Option<(ObjectId, &mut ObRecord<B>)>
where
    ObRecord<B>: Record,
{
    let (id, record) = pool.allocate_or_grow(0, pages()).ok()?;
    record.counts = Counts::created();
    record.sd = match security::take_pending() {
        Some(pending) => pending,
        None => fallback?,
    };
    Some((object_id(kind, id), record))
}

/// A new dispatcher object of `kind` in `pool`, holding its creator's reference, its body made in
/// the dispatcher database at the same index (before the id leaves here: every id names a made
/// body) and renewed there by `renew`, all in one raise to the dispatch level. None, with nothing
/// made, when no page is left for the record or the body (or the kind's u16 index is spent).
pub(super) fn create_dispatcher_object<B, const PER: usize>(
    pool: &mut ObSlots<B, PER>,
    kind: ObjectType,
    renew: impl FnOnce(&mut Dispatcher, u16),
) -> Option<ObjectId>
where
    ObRecord<B>: Record,
{
    let (id, _) = allocate_record(pool, kind, security::default_sd(kind))?;
    let body = id.waitable().expect("a dispatcher object's kind");
    let made = with_bodies(|bodies| {
        let made = bodies.ensure_body(body, pages()).is_ok();
        if made {
            renew(bodies, id.index);
        }
        made
    });
    if !made {
        // Undone: the record goes back as a deletion leaves it, its id stale before anyone saw it,
        // its descriptor's reference released with it (a freed record is overwritten, not
        // dropped).
        if let Some(record) = pool.get_mut(slot_id(id)) {
            record.sd = SdRef::NONE;
        }
        let freed = pool.free(slot_id(id));
        debug_assert!(freed, "the record just taken");
        return None;
    }
    Some(id)
}

/// A dispatcher object's record in the directory: its counts alone. Its body is the dispatcher
/// database's ([`crate::sched::database`]), in the kind's side table at the same index, as Windows
/// 2000 keeps a dispatcher object's DISPATCHER_HEADER apart from its object header. One type per
/// kind, so each kind has its pool.
pub struct EventObject;
/// A semaphore's record in the directory (see [`EventObject`]).
pub struct SemaphoreObject;
/// A mutex's record in the directory (see [`EventObject`]).
pub struct MutexObject;
/// A waitable timer's record in the directory (see [`EventObject`]).
pub struct TimerObject;
/// A process's record in the directory (see [`EventObject`]): its body is the dispatcher
/// database's, its thread ordinals the directory's own side table, its process record
/// [`crate::process::pool`]'s, each at the object's index.
pub struct ProcessRecord;

/// A thread's record in the directory (see [`EventObject`]): its record (KTHREAD) is the
/// dispatcher database's, its wait's references the directory's own side table, each at the
/// object's index.
pub struct ThreadRecord;

/// How the thread objects' pool hands out its indices: never the system threads' (the first
/// [`crate::sched::database::SYSTEM_THREADS`]), and the lowest free one first, so the dispatcher's
/// records stay packed in the chunks already made. No cap but the u16 index's 65,532 threads (a
/// representation limit; Windows 2000 has none but memory): the pages for the records and their
/// kernel stacks (12,743 at most, [`crate::mem::kstacks`]) run out long before, a refused create.
pub struct ThreadIndex;

impl Codec for ThreadIndex {
    type Id = Id<ThreadRecord>;

    const LANES: usize = 1;
    const MAX_INDEX: u32 = 0xFFFE;
    const MAX_UNIQ: u16 = 0xFFFE;
    const RESERVED_LOW: u32 = crate::sched::database::SYSTEM_THREADS as u32;
    const REUSE: Reuse = Reuse::Lowest;

    fn encode(index: u32, uniq: u16) -> Id<ThreadRecord> {
        Id::new(index as u16, uniq)
    }

    fn decode(id: Id<ThreadRecord>) -> Option<(u32, Match)> {
        Some((id.index as u32, Match::Exact(id.uniq)))
    }
}

/// How the process objects' pool hands out its indices: never the System process's
/// ([`SYSTEM_PROCESS_INDEX`]), and the lowest free one first, since the walks over the processes
/// (the reap's, the console's control events') go in index order. No cap but the u16 index's
/// 65,534 processes (a representation limit; Windows 2000 has none but memory): the pages for the
/// records, bodies and side tables run out long before, STATUS_INSUFFICIENT_RESOURCES.
pub struct ProcessIndex;

impl Codec for ProcessIndex {
    type Id = Id<ProcessRecord>;

    const LANES: usize = 1;
    const MAX_INDEX: u32 = 0xFFFE;
    const MAX_UNIQ: u16 = 0xFFFE;
    const RESERVED_LOW: u32 = SYSTEM_PROCESS_INDEX as u32 + 1;
    const REUSE: Reuse = Reuse::Lowest;

    fn encode(index: u32, uniq: u16) -> Id<ProcessRecord> {
        Id::new(index as u16, uniq)
    }

    fn decode(id: Id<ProcessRecord>) -> Option<(u32, Match)> {
        Some((id.index as u32, Match::Exact(id.uniq)))
    }
}
