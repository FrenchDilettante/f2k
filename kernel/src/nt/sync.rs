//! The named objects' create and open, which every named kind shares: a create binds a new object's
//! name in `\BaseNamedObjects` (or opens the live object the name binds, under OBJ_OPENIF), an open
//! finds the live object a name binds. The sections use them now (NtCreateSection, NtOpenSection);
//! the synchronization services (events, mutants, semaphores and timers) join them here.
//!
//! A create that opens an existing object of its name returns STATUS_OBJECT_NAME_EXISTS.

use super::attributes::{
    self, Resolved, MAX_NAME, OBJ_OPENIF, STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_TYPE_MISMATCH,
};
use super::call::{
    calling_process, NtResult, Status, UserAddr, UserPtr, STATUS_ACCESS_VIOLATION,
    STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use crate::ob::{self, ObjectId, ObjectType};

const STATUS_OBJECT_NAME_COLLISION: Status = Status(0xC000_0035);
const STATUS_INSUFFICIENT_RESOURCES: Status = Status(0xC000_009A);
const STATUS_OBJECT_NAME_EXISTS: u32 = 0x4000_0000;

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
