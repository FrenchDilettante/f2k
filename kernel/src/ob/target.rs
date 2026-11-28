//! The kernel's directory and the services' side of it: the lock, the references a service holds,
//! the follow-ups finished after the lock, and the current process's handles.

use core::num::NonZeroU32;
use core::ptr::NonNull;

use super::typed::signal_process_body;
use super::*;
use crate::interrupt::irql;
use crate::level::{At, Passive};
use crate::sched::mutex::MutexId;
use crate::sched::thread::ThreadId;
use crate::sched::timer::TimerId;
use crate::sched::wait::WaitableId;
use crate::status::NtStatus;
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
    let Some(file) = locked(|directory| directory.file(file_object).map(|file| file.disk())) else {
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
/// [`grant::grant_handle`]) and `inheritance`, and its creator's reference dropped — the
/// handle holds it from now on. A failure (the table is full, or the access check denied the
/// grant) takes the object back with it; none when there is no handle for it.
pub fn publish(
    process: &crate::process::Process,
    id: ObjectId,
    access: u32,
    inherit: bool,
) -> Option<NonZeroU32> {
    publish_checked(process, id, access, inherit).ok().flatten()
}

/// As [`publish`], telling the two failures apart: `Err` for the grant's own status (a denied
/// access check's, as [`grant::grant_handle`] answers it), `Ok(None)` for a full handle
/// table. The object goes back with the create either way.
pub fn publish_checked(
    process: &crate::process::Process,
    id: ObjectId,
    access: u32,
    inherit: bool,
) -> Result<Option<NonZeroU32>, NtStatus> {
    let granted = grant::grant_handle(process, id, access, true);
    // The create's captured descriptor went onto the object at its allocation; one left over
    // (an OBJ_OPENIF create that found the name bound made no object) is dropped.
    security::take_pending();
    let granted = match granted {
        Ok(granted) => granted,
        Err(status) => {
            // The grant denied: the creator's reference taken at the allocation goes back,
            // so the object dies with the create that made it.
            release(id);
            return Err(status);
        }
    };
    let handle = process.insert_object(id, granted, inherit);
    release(id);
    Ok(handle)
}

/// Open the object `id` names as a new handle in `process`, granted `access` (its generic
/// rights mapped: [`ObjectType::granted`], checked against the object's security descriptor
/// and the caller's token when the caller is in user mode: [`grant::grant_handle`]); none
/// when the table is full, the object is gone, or the access check denied the grant.
pub fn open(
    process: &crate::process::Process,
    id: ObjectId,
    access: u32,
    inherit: bool,
) -> Option<NonZeroU32> {
    let granted = grant::grant_handle(process, id, access, false);
    // An open's OBJECT_ATTRIBUTES descriptor is not stored on the existing object.
    security::take_pending();
    let granted = granted.ok()?;
    process.insert_object(id, granted, inherit)
}

/// The process `id` names has ended with `exit_status`: its object signals, once, and its
/// waiters wake. The process's own reference keeps the object, so the directory is not reached:
/// the last thread's exit signals it after retiring, when it must not be preempted.
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
