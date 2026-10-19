//! The synchronization services: events, mutants, semaphores and timers, named in
//! `\BaseNamedObjects` or not; the waits on any waitable object; the delays and the yield; handle
//! duplication; and user APCs. kernel32's waits, sleeps and object calls are Win32 code over these,
//! as on Windows 2000. The named objects' create and open are shared with the sections
//! (NtCreateSection, NtOpenSection).
//!
//! The answers are Windows 2000's statuses: a wait returns STATUS_WAIT_0 + n,
//! STATUS_ABANDONED_WAIT_0 + n, STATUS_TIMEOUT, STATUS_USER_APC or STATUS_ALERTED; a create that
//! opens an existing object of its name returns STATUS_OBJECT_NAME_EXISTS. A BOOLEAN argument is
//! its low byte, as the platform reads it. A timeout is a LARGE_INTEGER: negative a relative
//! interval in 100 ns units, positive an absolute system time, none (a null pointer) forever.

use super::attributes::{
    self, Resolved, MAX_NAME, OBJ_OPENIF, STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_TYPE_MISMATCH,
};
use super::call::{
    calling_process, Handle, NtCall, NtResult, Status, UserAddr, UserPtr, STATUS_ACCESS_VIOLATION,
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use crate::nt::object::{
    is_console_handle, names_current_process, CURRENT_PROCESS, CURRENT_THREAD,
};
use crate::ob::{self, ObjectId, ObjectType};
use crate::sched::event::{EventKind, EVENT_WAKE_INCREMENT};
use crate::sched::wait::{self, WaitMode, WaitReason, Waitable, MAXIMUM_WAIT_OBJECTS};

const STATUS_UNSUCCESSFUL: Status = Status(0xC000_0001);
const STATUS_NO_MEMORY: Status = Status(0xC000_0017);
const STATUS_INVALID_PARAMETER_MIX: Status = Status(0xC000_0030);
const STATUS_OBJECT_NAME_COLLISION: Status = Status(0xC000_0035);
const STATUS_SEMAPHORE_LIMIT_EXCEEDED: Status = Status(0xC000_0047);
const STATUS_INSUFFICIENT_RESOURCES: Status = Status(0xC000_009A);
const STATUS_INVALID_PARAMETER_1: Status = Status(0xC000_00EF);
const STATUS_INVALID_PARAMETER_3: Status = Status(0xC000_00F1);
const STATUS_OBJECT_NAME_EXISTS: u32 = 0x4000_0000;
const STATUS_TIMER_RESUME_IGNORED: u32 = 0x4000_0025;

/// The priority increment a semaphore release grants the waiters it wakes.
const SEMAPHORE_WAKE_INCREMENT: i8 = 1;

/// A BOOLEAN argument: its low byte.
fn boolean(value: u32) -> bool {
    value as u8 != 0
}

/// Probe `size` bytes at `at` for the call's writes, when given: STATUS_ACCESS_VIOLATION before the
/// call acts, as the platform's probes are.
pub(super) fn probe(at: u32, size: u32) -> Result<(), Status> {
    if at == 0 {
        return Ok(());
    }
    crate::user::syscall::probe_user_range(at, size).map_err(|_| STATUS_ACCESS_VIOLATION)
}

// --- Naming ---------------------------------------------------------------------------------------

/// What an OBJECT_ATTRIBUTES asks of a create or an open: the name in `\BaseNamedObjects` (its
/// bytes' length; none for an unnamed object), whether it names the directory itself, and the
/// handle's inheritance and OBJ_OPENIF.
struct Request {
    name: Option<usize>,
    directory: bool,
    inherit: bool,
    open_if: bool,
}

/// Read the request at `attributes` (none: an unnamed object, a handle not inherited), the name's
/// bytes into `out`.
fn request(attributes: UserAddr, out: &mut [u8; ob::MAX_NAME]) -> Result<Request, Status> {
    let mut request = Request {
        name: None,
        directory: false,
        inherit: false,
        open_if: false,
    };
    if attributes.is_null() {
        return Ok(request);
    }
    let mut units = [0u16; MAX_NAME];
    let read = attributes::read(attributes, &mut units)?;
    request.inherit = read.inherit();
    request.open_if = read.attributes & OBJ_OPENIF != 0;
    let Some(length) = read.length.filter(|&length| length > 0) else {
        return Ok(request);
    };
    let root_is_directory = attributes::root_is_directory(read.root)?;
    match attributes::resolve(&units[..length], read.root, root_is_directory)? {
        Resolved::Directory => request.directory = true,
        Resolved::Named { start } => {
            request.name = Some(attributes::object_name(&units[start..length], out)?)
        }
    }
    Ok(request)
}

/// The new handle into the caller's slot, with the call's status; a slot that faults takes the
/// handle back (STATUS_ACCESS_VIOLATION).
fn deliver(slot: UserPtr<u32>, handle: u32, status: u32) -> NtResult {
    if slot.write(handle).is_err() {
        calling_process().close_handle(handle);
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(status)
}

/// The create every named kind shares (NtCreateSection; NtCreateEvent, NtCreateMutant,
/// NtCreateSemaphore and NtCreateTimer as they come): a name that binds a live object opens it
/// under OBJ_OPENIF when the kinds agree (STATUS_OBJECT_NAME_EXISTS; the creation's other arguments
/// ignored) and is STATUS_OBJECT_TYPE_MISMATCH when they do not; without OBJ_OPENIF any bound name
/// is STATUS_OBJECT_NAME_COLLISION. Otherwise `make` creates the object, which is published: its
/// handle (with `access`) inserted and the name bound.
pub(super) fn create(
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    kind: ObjectType,
    make: impl FnOnce() -> Option<ObjectId>,
) -> NtResult {
    let mut bytes = [0u8; ob::MAX_NAME];
    let request = request(attributes, &mut bytes)?;
    probe(slot.addr().raw(), 4)?;
    let process = calling_process();
    // A full table refuses before an object is made.
    if process.handles().is_full() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    if request.directory {
        return Err(if request.open_if {
            STATUS_OBJECT_TYPE_MISMATCH
        } else {
            STATUS_OBJECT_NAME_COLLISION
        });
    }
    let name = request.name.map(|length| &bytes[..length]);
    if let Some(existing) = name.and_then(|name| ob::directory().lookup_name(name)) {
        if !request.open_if {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        if existing.kind != kind {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        return match ob::open(process, existing, access, request.inherit) {
            0 => Err(STATUS_INSUFFICIENT_RESOURCES),
            handle => deliver(slot, handle, STATUS_OBJECT_NAME_EXISTS),
        };
    }
    let id = make().ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let handle = ob::publish(process, id, access, request.inherit, name)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    deliver(slot, handle, STATUS_SUCCESS)
}

/// The open every named kind shares (NtOpenSection; NtOpenEvent, NtOpenMutant, NtOpenSemaphore
/// and NtOpenTimer as they come): a new handle to the live object the name binds, with the access
/// asked for. STATUS_OBJECT_NAME_NOT_FOUND when it binds none, STATUS_OBJECT_TYPE_MISMATCH when it
/// binds another kind (the directory included).
pub(super) fn open(
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    kind: ObjectType,
) -> NtResult {
    if attributes.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut bytes = [0u8; ob::MAX_NAME];
    let request = request(attributes, &mut bytes)?;
    probe(slot.addr().raw(), 4)?;
    if request.directory {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    let length = request.name.ok_or(STATUS_OBJECT_NAME_INVALID)?;
    let existing = ob::directory()
        .lookup_name(&bytes[..length])
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    if existing.kind != kind {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    match ob::open(calling_process(), existing, access, request.inherit) {
        0 => Err(STATUS_INSUFFICIENT_RESOURCES),
        handle => deliver(slot, handle, STATUS_SUCCESS),
    }
}

/// The object of `kind` `handle` names in the calling process, referenced for the caller's scope:
/// STATUS_INVALID_HANDLE for a handle naming nothing (a console handle included),
/// STATUS_OBJECT_TYPE_MISMATCH for one naming another kind.
pub(super) fn object_of(handle: u32, kind: ObjectType) -> Result<ob::ObRef, Status> {
    if is_console_handle(handle) {
        return Err(STATUS_INVALID_HANDLE);
    }
    let id = calling_process()
        .handles()
        .lookup(handle)
        .and_then(|entry| entry.object_id())
        .ok_or(STATUS_INVALID_HANDLE)?;
    if id.kind != kind {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    ob::reference(id).ok_or(STATUS_INVALID_HANDLE)
}

/// NtOpenDirectoryObject: `\BaseNamedObjects`, the one directory there is (made at its first open,
/// permanent). Any other name is STATUS_OBJECT_NAME_NOT_FOUND, an object's
/// STATUS_OBJECT_TYPE_MISMATCH.
pub fn open_directory_object(
    _call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
) -> NtResult {
    if attributes.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut bytes = [0u8; ob::MAX_NAME];
    let request = request(attributes, &mut bytes)?;
    probe(slot.addr().raw(), 4)?;
    if !request.directory {
        let length = request.name.ok_or(STATUS_OBJECT_NAME_INVALID)?;
        return Err(match ob::directory().lookup_name(&bytes[..length]) {
            Some(_) => STATUS_OBJECT_TYPE_MISMATCH,
            None => STATUS_OBJECT_NAME_NOT_FOUND,
        });
    }
    let id = ob::directory()
        .named_objects()
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    match ob::open(calling_process(), id, access, request.inherit) {
        0 => Err(STATUS_INSUFFICIENT_RESOURCES),
        handle => deliver(slot, handle, STATUS_SUCCESS),
    }
}

// --- Events ---------------------------------------------------------------------------------------

/// NtCreateEvent: a NotificationEvent (0, manual-reset) or a SynchronizationEvent (1, auto-reset),
/// signaled when asked; or the named one already bound (see [`create`]).
pub fn create_event(
    _call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    event_type: u32,
    initial_state: u32,
) -> NtResult {
    let kind = match event_type {
        0 => EventKind::Notification,
        1 => EventKind::Synchronization,
        _ => return Err(STATUS_INVALID_PARAMETER),
    };
    create(slot, access, attributes, ObjectType::Event, || {
        ob::directory().create_event(kind, boolean(initial_state))
    })
}

/// NtOpenEvent (see [`open`]).
pub fn open_event(
    _call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
) -> NtResult {
    open(slot, access, attributes, ObjectType::Event)
}

/// What the event services share: the event's previous state into `previous` when given (probed
/// before the event changes).
fn with_event(
    event: Handle,
    previous: UserPtr<i32>,
    change: impl FnOnce(&mut crate::sched::event::Event) -> i32,
) -> NtResult {
    probe(previous.addr().raw(), 4)?;
    let reference = object_of(event.raw(), ObjectType::Event)?;
    let was = change(reference.event());
    previous.write_optional(was)?;
    Ok(STATUS_SUCCESS)
}

/// NtSetEvent: signal the event, granting its waiters the event wake boost.
pub fn set_event(_call: &mut NtCall, event: Handle, previous: UserPtr<i32>) -> NtResult {
    with_event(event, previous, |event| {
        event.set(crate::sched::idle::dispatcher(), EVENT_WAKE_INCREMENT)
    })
}

/// NtResetEvent: clear the event; a waiter parked on it stays parked.
pub fn reset_event(_call: &mut NtCall, event: Handle, previous: UserPtr<i32>) -> NtResult {
    with_event(event, previous, |event| event.reset())
}

/// NtClearEvent: clear the event (NtResetEvent without the previous state; kernel32's ResetEvent
/// calls it).
pub fn clear_event(_call: &mut NtCall, event: Handle) -> NtResult {
    with_event(event, UserPtr::at(0), |event| event.reset())
}

/// NtPulseEvent: signal the event for the waiters present — all of them for a notification event,
/// one for a synchronization event — and leave it cleared either way.
pub fn pulse_event(_call: &mut NtCall, event: Handle, previous: UserPtr<i32>) -> NtResult {
    with_event(event, previous, |event| {
        let was = event.set(crate::sched::idle::dispatcher(), EVENT_WAKE_INCREMENT);
        event.reset();
        was
    })
}

// --- Mutants and semaphores -----------------------------------------------------------------------

/// NtCreateMutant: a fresh mutant, owned by the caller when asked, or the named one already bound
/// (whose ownership the call then leaves alone; see [`create`]).
pub fn create_mutant(
    _call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    initial_owner: u32,
) -> NtResult {
    create(slot, access, attributes, ObjectType::Mutex, || {
        let directory = ob::directory();
        let id = directory.create_mutex()?;
        if boolean(initial_owner) {
            // SAFETY: the running thread's record, live while it runs a service.
            let thread = unsafe { &mut *crate::sched::idle::dispatcher().current_thread() };
            crate::sched::mutex::acquire(directory.mutex(id).expect("just created"), thread);
        }
        Some(id)
    })
}

/// NtOpenMutant (see [`open`]).
pub fn open_mutant(
    _call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
) -> NtResult {
    open(slot, access, attributes, ObjectType::Mutex)
}

/// NtReleaseMutant: give up one unit of the caller's ownership (the last frees the mutant for its
/// oldest waiter); the previous count into `previous` when given. STATUS_MUTANT_NOT_OWNED unless
/// the caller owns it.
pub fn release_mutant(_call: &mut NtCall, mutant: Handle, previous: UserPtr<i32>) -> NtResult {
    probe(previous.addr().raw(), 4)?;
    let reference = object_of(mutant.raw(), ObjectType::Mutex)?;
    let dispatcher = crate::sched::idle::dispatcher();
    let was = dispatcher
        .release_mutex(reference.mutex(), dispatcher.current_thread())
        .map_err(|status| Status(status as u32))?;
    previous.write_optional(was)?;
    Ok(STATUS_SUCCESS)
}

/// NtCreateSemaphore: a fresh semaphore at the initial count with the given maximum, or the named
/// one already bound (see [`create`]). STATUS_INVALID_PARAMETER unless 0 <= initial <= maximum and
/// the maximum is positive.
pub fn create_semaphore(
    _call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    initial: i32,
    maximum: i32,
) -> NtResult {
    if maximum <= 0 || initial < 0 || initial > maximum {
        return Err(STATUS_INVALID_PARAMETER);
    }
    create(slot, access, attributes, ObjectType::Semaphore, || {
        ob::directory().create_semaphore(initial, maximum)
    })
}

/// NtOpenSemaphore (see [`open`]).
pub fn open_semaphore(
    _call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
) -> NtResult {
    open(slot, access, attributes, ObjectType::Semaphore)
}

/// NtReleaseSemaphore: add the count, waking as many waiters as it covers; the previous count into
/// `previous` when given. STATUS_INVALID_PARAMETER for a count that is not positive,
/// STATUS_SEMAPHORE_LIMIT_EXCEEDED past the maximum (the count unchanged, `previous` unwritten).
pub fn release_semaphore(
    _call: &mut NtCall,
    semaphore: Handle,
    count: i32,
    previous: UserPtr<i32>,
) -> NtResult {
    probe(previous.addr().raw(), 4)?;
    if count <= 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let reference = object_of(semaphore.raw(), ObjectType::Semaphore)?;
    let was = crate::sched::idle::dispatcher()
        .release_semaphore(reference.semaphore(), count, SEMAPHORE_WAKE_INCREMENT)
        .map_err(|_| STATUS_SEMAPHORE_LIMIT_EXCEEDED)?;
    previous.write_optional(was)?;
    Ok(STATUS_SUCCESS)
}

// --- Timers ---------------------------------------------------------------------------------------

/// NtCreateTimer: a NotificationTimer (0, manual-reset) or a SynchronizationTimer (1, auto-reset),
/// unarmed, or the named one already bound (see [`create`]).
pub fn create_timer(
    _call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    timer_type: u32,
) -> NtResult {
    let manual_reset = match timer_type {
        0 => true,
        1 => false,
        _ => return Err(STATUS_INVALID_PARAMETER),
    };
    create(slot, access, attributes, ObjectType::Timer, || {
        ob::directory().create_timer(manual_reset)
    })
}

/// NtOpenTimer (see [`open`]).
pub fn open_timer(
    _call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
) -> NtResult {
    open(slot, access, attributes, ObjectType::Timer)
}

/// Write a BOOLEAN out argument, when given.
fn write_boolean(at: UserAddr, value: bool) -> Result<(), Status> {
    if !at.is_null() {
        at.write(&[u8::from(value)])?;
    }
    Ok(())
}

/// NtSetTimer: arm the timer (see [`crate::sched::waitable_timer`]). The due time is absolute (a
/// system time) when positive, relative when negative, both on the timer table's one clock (see
/// [`wait::due_time`]); the period is in milliseconds, zero for a one-shot. A completion routine is
/// queued to the calling thread at each expiry, with its context and the time the timer was
/// signaled (a FILETIME's low and high dwords). Whether the timer was armed before goes into
/// `previous` when given. The resume flag is not supported: the set succeeds with
/// STATUS_TIMER_RESUME_IGNORED, as on a machine without power management.
/// STATUS_INVALID_PARAMETER for a negative period.
#[allow(clippy::too_many_arguments)]
pub fn set_timer(
    _call: &mut NtCall,
    timer: Handle,
    due_time: UserPtr<u64>,
    routine: UserAddr,
    context: UserAddr,
    resume: u32,
    period: i32,
    previous: UserAddr,
) -> NtResult {
    probe(previous.raw(), 1)?;
    let reference = object_of(timer.raw(), ObjectType::Timer)?;
    let due = due_time.read()? as i64;
    if period < 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let timer = reference.timer();
    let now = crate::interrupt::clock::interrupt_time();
    let signal_time = crate::time::system_filetime();
    let due = wait::due_time(due, now, signal_time);
    let dispatcher = crate::sched::idle::dispatcher();
    // The cancel first: the APC record may still be queued from the previous set.
    let armed = dispatcher.cancel_waitable_timer(timer);
    let completion = !routine.is_null();
    if completion {
        crate::user::apc::init(
            &mut timer.apc,
            dispatcher.current_thread(),
            routine.raw(),
            context.raw(),
        );
    }
    dispatcher.set_waitable_timer(
        timer,
        due,
        now,
        period as u64 * 10_000,
        completion,
        signal_time,
    );
    write_boolean(previous, armed)?;
    Ok(if boolean(resume) {
        STATUS_TIMER_RESUME_IGNORED
    } else {
        STATUS_SUCCESS
    })
}

/// NtCancelTimer: disarm the timer, its period and any queued completion APC dropped; the signal
/// state is left as it was, and goes into `current` when given.
pub fn cancel_timer(_call: &mut NtCall, timer: Handle, current: UserAddr) -> NtResult {
    probe(current.raw(), 1)?;
    let reference = object_of(timer.raw(), ObjectType::Timer)?;
    let timer = reference.timer();
    crate::sched::idle::dispatcher().cancel_waitable_timer(timer);
    // SAFETY: the timer's own waitable header, live while the reference is held.
    let signaled = unsafe { (*timer.waitable()).signal_state() } > 0;
    write_boolean(current, signaled)?;
    Ok(STATUS_SUCCESS)
}

// --- Waits ----------------------------------------------------------------------------------------

/// A timeout argument as the waits take it: none (a null pointer) waits forever; otherwise the
/// interval from now, in 100 ns units — negative values are relative already, positive ones an
/// absolute system time (a time already past is a past due, which the waits complete at once).
/// The longest relative interval stays the far future the wrap-safe due arithmetic makes it.
fn timeout_of(at: UserPtr<u64>) -> Result<Option<i64>, Status> {
    if at.is_null() {
        return Ok(None);
    }
    Ok(Some(interval_of(at.read()? as i64)))
}

/// A LARGE_INTEGER interval (see [`timeout_of`]) as a relative one.
fn interval_of(value: i64) -> i64 {
    if value <= 0 {
        value.wrapping_neg()
    } else {
        (value as u64).wrapping_sub(crate::time::system_filetime()) as i64
    }
}

/// The waitable a handle names, with the object it belongs to (the wait holds it): a table
/// object's header, or the thread and process pseudo-handles' own objects. STATUS_INVALID_HANDLE
/// for a handle naming nothing (a console handle included), STATUS_OBJECT_TYPE_MISMATCH for an
/// object no wait can name (a file, a section, the directory).
fn waitable_of(handle: u32) -> Result<(Option<ObjectId>, *mut Waitable), Status> {
    let id = match handle {
        CURRENT_THREAD => ob::current_thread().ok_or(STATUS_INVALID_HANDLE)?,
        CURRENT_PROCESS => crate::process::current().object(),
        _ if is_console_handle(handle) => return Err(STATUS_INVALID_HANDLE),
        _ => calling_process()
            .handles()
            .lookup(handle)
            .and_then(|entry| entry.object_id())
            .ok_or(STATUS_INVALID_HANDLE)?,
    };
    let waitable = ob::directory()
        .waitable(id)
        .ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
    Ok((Some(id), waitable))
}

/// The single-object wait: the status as the wait completes it. A blocking wait parks the calling
/// thread; a kernel APC breaks it and the shared entry replays it after the delivery, the deadline
/// preserved. The wait holds its object throughout, replays included: a handle closed meanwhile
/// leaves it waiting on a live object.
fn wait_one(
    (object, waitable): (Option<ObjectId>, *mut Waitable),
    timeout: Option<i64>,
    alertable: bool,
) -> u32 {
    let held = object.as_slice();
    ob::waiting(held, || {
        wait::wait_current_with(|dispatcher, thread, stamp, replay| {
            let timeout = wait::replay_timeout(thread, replay, timeout, stamp.interrupt_time);
            dispatcher.wait_single(
                thread,
                waitable,
                WaitReason::UserRequest,
                WaitMode::User,
                alertable,
                timeout,
                stamp,
            )
        }) as u32
    })
}

/// NtWaitForSingleObject: wait on the object the handle names (the thread and process
/// pseudo-handles included), alertably when asked — a user APC queued on the caller (or arriving
/// while it waits) runs, and the wait returns STATUS_USER_APC.
pub fn wait_for_single_object(
    _call: &mut NtCall,
    object: Handle,
    alertable: u32,
    timeout: UserPtr<u64>,
) -> NtResult {
    let timeout = timeout_of(timeout)?;
    let waitable = waitable_of(object.raw())?;
    Ok(wait_one(waitable, timeout, boolean(alertable)))
}

/// NtWaitForMultipleObjects: wait on up to 64 objects at once — WaitAny (1: the lowest signaled
/// index, STATUS_WAIT_0 + n or STATUS_ABANDONED_WAIT_0 + n) or WaitAll (0: STATUS_WAIT_0, every
/// object taken at once). STATUS_INVALID_PARAMETER_1 for no objects or more than 64,
/// STATUS_INVALID_PARAMETER_3 for another wait type, STATUS_INVALID_PARAMETER_MIX for a wait-all
/// naming an object twice.
pub fn wait_for_multiple_objects(
    _call: &mut NtCall,
    count: u32,
    handles: UserAddr,
    wait_type: u32,
    alertable: u32,
    timeout: UserPtr<u64>,
) -> NtResult {
    let count = count as usize;
    if count == 0 || count > MAXIMUM_WAIT_OBJECTS {
        return Err(STATUS_INVALID_PARAMETER_1);
    }
    let wait_all = match wait_type {
        0 => true,
        1 => false,
        _ => return Err(STATUS_INVALID_PARAMETER_3),
    };
    let timeout = timeout_of(timeout)?;
    let mut raw = [0u8; MAXIMUM_WAIT_OBJECTS * 4];
    handles.read(&mut raw[..count * 4])?;
    let mut objects = [core::ptr::null_mut(); MAXIMUM_WAIT_OBJECTS];
    let mut held = [ObjectId {
        kind: ObjectType::Event,
        index: 0,
        generation: 0,
    }; MAXIMUM_WAIT_OBJECTS];
    let mut holding = 0;
    for (object, handle) in objects.iter_mut().zip(raw.chunks_exact(4)).take(count) {
        let handle = u32::from_le_bytes([handle[0], handle[1], handle[2], handle[3]]);
        let (id, waitable) = waitable_of(handle)?;
        *object = waitable;
        if let Some(id) = id {
            held[holding] = id;
            holding += 1;
        }
    }
    let objects = &objects[..count];
    if wait_all && (1..count).any(|index| objects[..index].contains(&objects[index])) {
        return Err(STATUS_INVALID_PARAMETER_MIX);
    }
    let alertable = boolean(alertable);
    // The wait holds every object it names throughout, replays included.
    let status = ob::waiting(&held[..holding], || {
        wait::wait_current_with(|dispatcher, thread, stamp, replay| {
            let timeout = wait::replay_timeout(thread, replay, timeout, stamp.interrupt_time);
            dispatcher.wait_multiple(
                thread,
                objects,
                wait_all,
                WaitReason::UserRequest,
                WaitMode::User,
                alertable,
                timeout,
                stamp,
            )
        })
    });
    Ok(status as u32)
}

/// NtSignalAndWaitForSingleObject: signal one object — set an event, release a semaphore by one,
/// or release a mutant — and wait on another, with nothing running in between (the gate runs with
/// interrupts masked, and the woken thread runs only once the caller parks). The signal's own
/// refusals fail the call before any wait: STATUS_SEMAPHORE_LIMIT_EXCEEDED,
/// STATUS_MUTANT_NOT_OWNED, or STATUS_OBJECT_TYPE_MISMATCH for an object that cannot be signaled.
pub fn signal_and_wait_for_single_object(
    _call: &mut NtCall,
    signal: Handle,
    wait: Handle,
    alertable: u32,
    timeout: UserPtr<u64>,
) -> NtResult {
    let timeout = timeout_of(timeout)?;
    let waitable = waitable_of(wait.raw())?;
    let signal = signal.raw();
    let dispatcher = crate::sched::idle::dispatcher();
    let kind = if is_console_handle(signal) {
        None
    } else {
        calling_process()
            .handles()
            .lookup(signal)
            .and_then(|entry| entry.object_id())
            .map(|id| id.kind)
    };
    match kind {
        Some(ObjectType::Event) => {
            object_of(signal, ObjectType::Event)?
                .event()
                .set(dispatcher, EVENT_WAKE_INCREMENT);
        }
        Some(ObjectType::Semaphore) => {
            let semaphore = object_of(signal, ObjectType::Semaphore)?;
            dispatcher
                .release_semaphore(semaphore.semaphore(), 1, SEMAPHORE_WAKE_INCREMENT)
                .map_err(|_| STATUS_SEMAPHORE_LIMIT_EXCEEDED)?;
        }
        Some(ObjectType::Mutex) => {
            let mutex = object_of(signal, ObjectType::Mutex)?;
            dispatcher
                .release_mutex(mutex.mutex(), dispatcher.current_thread())
                .map_err(|status| Status(status as u32))?;
        }
        Some(_) => return Err(STATUS_OBJECT_TYPE_MISMATCH),
        None => return Err(STATUS_INVALID_HANDLE),
    }
    Ok(wait_one(waitable, timeout, boolean(alertable)))
}

/// NtDelayExecution: park the calling thread for the interval (see [`timeout_of`]) — the delay
/// discipline on the caller's own timer. An interval already past is the pure yield; the longest
/// relative one parks for good. A kernel APC breaks the delay and the shared entry replays it with
/// the remaining time; the delay completes as STATUS_SUCCESS, or STATUS_USER_APC when an alertable
/// one ran user APCs.
pub fn delay_execution(_call: &mut NtCall, alertable: u32, interval: UserPtr<u64>) -> NtResult {
    let interval = interval_of(interval.read()? as i64);
    let alertable = boolean(alertable);
    let status = wait::wait_current_with(|dispatcher, thread, stamp, replay| {
        let interval = if replay {
            wait::replay_interval(thread.timer.due_time, stamp.interrupt_time)
        } else {
            interval
        };
        dispatcher.delay(thread, WaitMode::User, alertable, interval, stamp)
    });
    Ok(crate::sched::dispatcher::Dispatcher::delay_completed(status) as u32)
}

/// NtYieldExecution: hand the processor to any ready thread, a lower-priority one included (see
/// [`crate::sched::dispatcher::Dispatcher::yield_execution`]). STATUS_SUCCESS when another thread
/// ran, STATUS_NO_YIELD_PERFORMED when none was ready.
pub fn yield_execution(_call: &mut NtCall) -> NtResult {
    let status = wait::wait_current_with(|dispatcher, thread, _stamp, _replay| {
        if dispatcher.yield_execution(thread) {
            thread.wait_status = crate::status::STATUS_SUCCESS;
            wait::WaitDisposition::Yield
        } else {
            wait::WaitDisposition::Complete(crate::status::STATUS_NO_YIELD_PERFORMED)
        }
    });
    Ok(status as u32)
}

// --- Handles and APCs -----------------------------------------------------------------------------

/// NtDuplicateObject, within the calling process: a new handle naming the same object (the
/// current-thread and current-process pseudo-handles duplicate to real handles to their objects),
/// with the access asked for or the source's (DUPLICATE_SAME_ACCESS), inheritable as the
/// attributes say (OBJ_INHERIT), optionally closing the source (DUPLICATE_CLOSE_SOURCE), which a
/// found source is whatever happens next (see [`super::object::duplicate_entry`]); with no target
/// process, closing it is all the call does. A target handle the probe refuses fails the call
/// before anything is looked up. Other processes are not reachable.
#[allow(clippy::too_many_arguments)]
pub fn duplicate_object(
    _call: &mut NtCall,
    source_process: Handle,
    source: Handle,
    target_process: Handle,
    target: UserPtr<u32>,
    access: u32,
    attributes: u32,
    options: u32,
) -> NtResult {
    use super::object::{duplicate_entry, DuplicateTable, TargetProcess};
    use crate::ob::Target;

    /// The calling process's table: an object's handle counts on the object (a file object's
    /// duplicate shares its position, as the files fixture's handles block shows).
    struct Calling;
    impl DuplicateTable for Calling {
        fn insert(&mut self, entry: ob::Entry) -> u32 {
            let Target::Object(id) = entry.target;
            calling_process().insert_object(id, entry.access, entry.inherit)
        }

        fn close(&mut self, handle: u32) {
            calling_process().close_handle(handle);
        }
    }

    let source = source.raw();
    probe(target.addr().raw(), 4)?;
    if !names_current_process(source_process.raw()) {
        return Err(STATUS_INVALID_HANDLE);
    }
    let entry = if source == CURRENT_THREAD {
        let id = ob::current_thread().ok_or(STATUS_INVALID_HANDLE)?;
        ob::Entry::object(id, ob::THREAD_ALL_ACCESS, false)
    } else if source == CURRENT_PROCESS {
        // The pseudo-handle becomes a real handle to the process's object.
        ob::Entry::object(
            crate::process::current().object(),
            ob::PROCESS_ALL_ACCESS,
            false,
        )
    } else if is_console_handle(source) {
        return Err(STATUS_INVALID_HANDLE);
    } else {
        calling_process()
            .handles()
            .lookup(source)
            .ok_or(STATUS_INVALID_HANDLE)?
    };
    let closable = (source != CURRENT_THREAD && source != CURRENT_PROCESS).then_some(source);
    let target_process = match target_process.raw() {
        0 => TargetProcess::None,
        handle if names_current_process(handle) => TargetProcess::Current,
        _ => TargetProcess::Invalid,
    };
    duplicate_entry(
        &mut Calling,
        entry,
        closable,
        target_process,
        access,
        attributes,
        options,
        |handle| target.write_optional(handle),
    )
}

/// NtQueueApcThread: queue `routine` on the thread's user-APC queue, with its three arguments; it
/// runs when that thread next waits alertably (or before its first instruction, if it never ran),
/// and a thread waiting alertably now is woken for it. STATUS_INVALID_HANDLE for a handle
/// naming no thread, STATUS_NO_MEMORY with no free APC record, STATUS_UNSUCCESSFUL for a thread
/// that has ended.
pub fn queue_apc_thread(
    call: &mut NtCall,
    thread: Handle,
    routine: UserAddr,
    argument1: UserAddr,
    argument2: UserAddr,
    argument3: UserAddr,
) -> NtResult {
    let reference = if thread.raw() == CURRENT_THREAD {
        ob::current_thread()
            .and_then(ob::reference)
            .ok_or(STATUS_INVALID_HANDLE)?
    } else {
        object_of(thread.raw(), ObjectType::Thread)?
    };
    let target = reference.thread() as *mut crate::sched::thread::Thread;
    let apc = call
        .process()
        .sync_mut()
        .free_apc()
        .ok_or(STATUS_NO_MEMORY)?;
    crate::user::apc::init(apc, target, routine.raw(), argument1.raw());
    let dispatcher = crate::sched::idle::dispatcher();
    if dispatcher.queue_apc(apc, argument2.raw() as usize, argument3.raw() as usize, 0) {
        Ok(STATUS_SUCCESS)
    } else {
        Err(STATUS_UNSUCCESSFUL)
    }
}
