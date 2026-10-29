//! The object services every handle shares: NtClose, and the handle side of NtDuplicateObject
//! (the service itself is `sync`'s, between the handle tables of the processes it names); and
//! which process a process handle names.
//!
//! A process handle is the pseudo-handle NtCurrentProcess (-1: the calling process, every access
//! granted), or a handle in the calling process's table to a process object — any process, the
//! caller's own among them. A service references the process with the access it needs, as Windows'
//! ObReferenceObjectByHandle does, checked in its order: a handle naming nothing is
//! STATUS_INVALID_HANDLE, one naming another kind of object STATUS_OBJECT_TYPE_MISMATCH, one not
//! granted the access STATUS_ACCESS_DENIED. The reference holds the process's object, and with it
//! its record (see [`crate::process::pool`]), for the service's scope; a process that has ended —
//! its object signalled — has no address space to reach (Windows deletes it at the process's
//! exit): the services that need it answer STATUS_PROCESS_IS_TERMINATING, ntstatus.h's "an attempt
//! was made to access an exiting process".

use super::call::{Fault, Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::ob::{Entry, ObjectId, ObjectType};
use crate::status::*;

/// NtDuplicateObject's options: close the source handle, and give the duplicate the source's
/// access.
pub const DUPLICATE_CLOSE_SOURCE: u32 = 1;
pub const DUPLICATE_SAME_ACCESS: u32 = 2;

/// The process access rights (winnt.h's PROCESS_*).
pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
pub const PROCESS_CREATE_PROCESS: u32 = 0x0080;
pub const PROCESS_SET_QUOTA: u32 = 0x0100;
pub const PROCESS_SET_INFORMATION: u32 = 0x0200;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

/// The standard and generic rights a process access mask may carry.
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_READ: u32 = 0x8000_0000;

/// The process access a mask amounts to: its generic rights mapped as the process type maps them
/// (read: querying and reading memory; write: changing the process, its memory and its handles;
/// execute: waiting on it; all, or the maximum allowed — no security descriptor restricts it —:
/// PROCESS_ALL_ACCESS), its specific and standard rights as they are.
pub fn process_access(access: u32) -> u32 {
    let mut granted = access & 0x00FF_FFFF;
    if access & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
        granted |= crate::ob::PROCESS_ALL_ACCESS;
    }
    if access & GENERIC_READ != 0 {
        granted |= READ_CONTROL | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
    }
    if access & GENERIC_WRITE != 0 {
        granted |= READ_CONTROL
            | PROCESS_TERMINATE
            | PROCESS_CREATE_THREAD
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_DUP_HANDLE
            | PROCESS_CREATE_PROCESS
            | PROCESS_SET_QUOTA
            | PROCESS_SET_INFORMATION;
    }
    if access & GENERIC_EXECUTE != 0 {
        granted |= READ_CONTROL | SYNCHRONIZE;
    }
    granted
}

/// The process object a handle-table entry names, when the entry grants `needed`: a missing entry
/// is STATUS_INVALID_HANDLE, an entry naming another kind of object STATUS_OBJECT_TYPE_MISMATCH,
/// one whose access lacks a right `needed` asks STATUS_ACCESS_DENIED — Windows' checks, in that
/// order.
pub fn process_of_entry(entry: Option<Entry>, needed: u32) -> Result<ObjectId, NtStatus> {
    let entry = entry.ok_or(STATUS_INVALID_HANDLE)?;
    let id = entry.object_id().ok_or(STATUS_INVALID_HANDLE)?;
    if id.kind != ObjectType::Process {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    if process_access(entry.access) & needed != needed {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(id)
}

/// A process a process handle names, referenced for the service's scope (see the module notes).
#[cfg(target_arch = "x86")]
pub struct ProcessRef {
    reference: crate::ob::ObRef,
    /// Whether it is the calling process.
    current: bool,
}

#[cfg(target_arch = "x86")]
impl ProcessRef {
    /// The process's object.
    pub fn id(&self) -> ObjectId {
        self.reference.id()
    }

    /// Whether it is the calling process.
    pub fn is_current(&self) -> bool {
        self.current
    }

    /// The process's record, live while the reference holds its object: for the calling process,
    /// the record [`NtCall::process`] answers too.
    pub fn record(&self) -> &'static crate::process::Process {
        crate::process::pool::of_object(self.id()).expect("a referenced process has its record")
    }

    /// The process's exit status: STILL_ACTIVE until it ends, its exit code after.
    pub fn exit_status(&self) -> u32 {
        let body = self.reference.process();
        crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
            crate::sched::DISPATCHER
                .get(dispatch)
                .process_object_mut(body)
                .exit_status
        })
    }

    /// Whether the process has ended: its object has signalled (at its last thread's exit).
    pub fn ended(&self) -> bool {
        let body = crate::sched::wait::WaitableId::Process(self.reference.process());
        crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
            crate::sched::DISPATCHER
                .get(dispatch)
                .waitable(body)
                .signal_state()
                > 0
        })
    }

    /// Run `body`, which reaches the process's address space ([`ProcessRef::reach`]): for another
    /// process, inside a critical region, so the thread cannot end attached (a termination
    /// requested meanwhile waits for the region's end). STATUS_PROCESS_IS_TERMINATING for a process
    /// that has ended: its address space is gone, or going.
    pub fn visit<R>(&self, body: impl FnOnce() -> Result<R, NtStatus>) -> Result<R, NtStatus> {
        if self.ended() {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        if self.current {
            body()
        } else {
            crate::process::threads::critical_region(body)
        }
    }

    /// Run `access` with the process's address space the live one: the calling process's already
    /// is; another process's is attached to for the scope (see [`crate::sched::attach`]), whose
    /// teardown waits for the scope's end ([`crate::process::pool`]). Only inside
    /// [`ProcessRef::visit`].
    pub fn reach<R>(&self, access: impl FnOnce() -> R) -> R {
        if self.current {
            return access();
        }
        let _attached = self.record().attach();
        access()
    }

    /// Run `body` over the process's record, its address space the live one throughout (see
    /// [`ProcessRef::visit`] and [`ProcessRef::reach`]).
    pub fn attached<R>(
        &self,
        body: impl FnOnce(&'static crate::process::Process) -> Result<R, NtStatus>,
    ) -> Result<R, NtStatus> {
        self.visit(|| self.reach(|| body(self.record())))
    }
}

/// Reference the process `handle` names (see the module notes), checking it grants `needed`: the
/// pseudo-handle names the calling process with every access; a console handle names nothing.
#[cfg(target_arch = "x86")]
pub fn reference_process(handle: u32, needed: u32) -> Result<ProcessRef, NtStatus> {
    let calling = crate::process::current();
    let id = match handle {
        CURRENT_PROCESS => calling.object(),
        _ if is_console_handle(handle) => return Err(STATUS_INVALID_HANDLE),
        _ => process_of_entry(calling.lookup_handle(handle), needed)?,
    };
    let reference = crate::ob::reference(id).ok_or(STATUS_INVALID_HANDLE)?;
    Ok(ProcessRef {
        reference,
        current: id == calling.object(),
    })
}

/// NtCurrentThread's pseudo-handle (GetCurrentThread's): the calling thread, in every thread
/// service.
pub const CURRENT_THREAD: u32 = 0xFFFF_FFFE;
/// The current-process pseudo-handle (NtCurrentProcess).
pub const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;

/// Whether `handle` is a console handle (the console server's pseudo-handles: the low two tag
/// bits set, bit 28 clear — so INVALID_HANDLE_VALUE is not one). Console handles are the console
/// server's, never decoded as object-table handles.
pub(crate) fn is_console_handle(handle: u32) -> bool {
    handle & 0x1000_0003 == 0x3
}

/// Whether `handle` names the calling process, in host builds: they have no process table, so only
/// the pseudo-handle does (the target's services reference the process a handle names instead,
/// see [`reference_process`]).
#[cfg(not(target_arch = "x86"))]
pub(crate) fn names_current_process(handle: u32) -> bool {
    handle == CURRENT_PROCESS
}

/// NtClose: the handle's entry released from the calling process's handle table (the object goes
/// once its last reference does). STATUS_INVALID_HANDLE for a handle naming no entry,
/// STATUS_HANDLE_NOT_CLOSABLE for one protected from close (see [`set_information_object`]), left
/// open.
pub fn close(call: &mut NtCall, handle: Handle) -> NtResult {
    #[cfg(target_arch = "x86")]
    {
        let process = call.process();
        let entry = process
            .lookup_handle(handle.raw())
            .ok_or(STATUS_INVALID_HANDLE)?;
        closable(entry)?;
        if process.close_handle(handle.raw()) {
            Ok(STATUS_SUCCESS)
        } else {
            Err(STATUS_INVALID_HANDLE)
        }
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (call, handle);
        Err(STATUS_INVALID_HANDLE)
    }
}

/// Whether NtClose may close the handle an entry is: not when it is protected from close.
pub fn closable(entry: Entry) -> Result<(), NtStatus> {
    if entry.protect_from_close {
        Err(STATUS_HANDLE_NOT_CLOSABLE)
    } else {
        Ok(())
    }
}

/// OBJECT_INFORMATION_CLASS: ObjectHandleFlagInformation, the one class NtQueryObject and
/// NtSetInformationObject answer here.
pub const OBJECT_HANDLE_FLAG_INFORMATION: u32 = 4;

/// OBJECT_HANDLE_FLAG_INFORMATION: a handle's two attributes, as BOOLEANs.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectHandleFlagInformation {
    pub inherit: u8,
    pub protect_from_close: u8,
}

/// The structure's size in bytes.
pub const OBJECT_HANDLE_FLAG_INFORMATION_SIZE: u32 =
    core::mem::size_of::<ObjectHandleFlagInformation>() as u32;
const _: () = assert!(OBJECT_HANDLE_FLAG_INFORMATION_SIZE == 2);

impl ObjectHandleFlagInformation {
    /// An entry's attributes.
    pub fn of(entry: Entry) -> Self {
        ObjectHandleFlagInformation {
            inherit: u8::from(entry.inherit),
            protect_from_close: u8::from(entry.protect_from_close),
        }
    }

    /// `entry` with these attributes (a BOOLEAN is TRUE when nonzero).
    pub fn applied_to(self, entry: Entry) -> Entry {
        Entry {
            inherit: self.inherit != 0,
            protect_from_close: self.protect_from_close != 0,
            ..entry
        }
    }

    /// The structure's bytes, as the caller's buffer holds them.
    pub fn to_bytes(self) -> [u8; 2] {
        [self.inherit, self.protect_from_close]
    }

    /// The structure, from the caller's bytes.
    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        ObjectHandleFlagInformation {
            inherit: bytes[0],
            protect_from_close: bytes[1],
        }
    }
}

/// What NtQueryObject and NtSetInformationObject do with their length: a query takes any buffer
/// with room for the structure (the bytes past it untouched), a set the structure's size exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagLength {
    AtLeast,
    Exactly,
}

/// The checks NtQueryObject and NtSetInformationObject make of their class and length before the
/// handle: a class other than ObjectHandleFlagInformation is STATUS_INVALID_INFO_CLASS (the
/// others, the object's basic, name, type and all-types information, are not answered here), a
/// length the service does not take (see [`FlagLength`]) STATUS_INFO_LENGTH_MISMATCH.
pub fn handle_flag_arguments(class: u32, length: u32, rule: FlagLength) -> Result<(), NtStatus> {
    if class != OBJECT_HANDLE_FLAG_INFORMATION {
        return Err(STATUS_INVALID_INFO_CLASS);
    }
    let taken = match rule {
        FlagLength::AtLeast => length >= OBJECT_HANDLE_FLAG_INFORMATION_SIZE,
        FlagLength::Exactly => length == OBJECT_HANDLE_FLAG_INFORMATION_SIZE,
    };
    if !taken {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    Ok(())
}

/// The flags NtQueryObject answers for a pseudo-handle, which has no entry to read them from: none
/// set (Windows 2000 answers the current process's pseudo-handle so). None for any other handle.
pub fn pseudo_handle_flags(handle: u32) -> Option<ObjectHandleFlagInformation> {
    matches!(handle, CURRENT_PROCESS | CURRENT_THREAD).then_some(ObjectHandleFlagInformation {
        inherit: 0,
        protect_from_close: 0,
    })
}

/// NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength,
/// ReturnLength): ObjectHandleFlagInformation alone: the handle's inheritance and its protection
/// from close, from its entry in the calling process's handle table (kernel32's
/// GetHandleInformation), its size written to ReturnLength when given. The class and length are
/// checked first (see [`handle_flag_arguments`]: a buffer too short still has the size written to
/// ReturnLength, as the service's documentation has it), then the handle: a pseudo-handle answers
/// no flags set ([`pseudo_handle_flags`]), any other handle naming no entry (a console handle has
/// none) is STATUS_INVALID_HANDLE. Only the structure's bytes are written, whatever the buffer's
/// length.
pub fn query_object(
    call: &mut NtCall,
    handle: Handle,
    class: u32,
    information: UserAddr,
    length: u32,
    return_length: UserPtr<u32>,
) -> NtResult {
    if let Err(status) = handle_flag_arguments(class, length, FlagLength::AtLeast) {
        if status == STATUS_INFO_LENGTH_MISMATCH {
            return_length.write_optional(OBJECT_HANDLE_FLAG_INFORMATION_SIZE)?;
        }
        return Err(status);
    }
    let flags = match pseudo_handle_flags(handle.raw()) {
        Some(flags) => flags,
        None => handle_entry_flags(call, handle)?,
    };
    information.write(&flags.to_bytes())?;
    return_length.write_optional(OBJECT_HANDLE_FLAG_INFORMATION_SIZE)?;
    Ok(STATUS_SUCCESS)
}

/// The flags of the entry `handle` names in the calling process's handle table;
/// STATUS_INVALID_HANDLE for a handle naming none.
fn handle_entry_flags(
    call: &mut NtCall,
    handle: Handle,
) -> Result<ObjectHandleFlagInformation, NtStatus> {
    #[cfg(target_arch = "x86")]
    {
        call.process()
            .lookup_handle(handle.raw())
            .map(ObjectHandleFlagInformation::of)
            .ok_or(STATUS_INVALID_HANDLE)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (call, handle);
        Err(STATUS_INVALID_HANDLE)
    }
}

/// NtSetInformationObject(Handle, ObjectInformationClass, ObjectInformation,
/// ObjectInformationLength): ObjectHandleFlagInformation alone: the handle's entry in the calling
/// process's handle table takes the structure's inheritance (what a child process created with
/// inheritance takes) and protection from close (NtClose refuses it: see [`close`]); kernel32's
/// SetHandleInformation. The class and length first (see [`handle_flag_arguments`]: the
/// structure's size exactly), then the caller's structure, then the handle (STATUS_INVALID_HANDLE
/// for one naming no entry).
pub fn set_information_object(
    call: &mut NtCall,
    handle: Handle,
    class: u32,
    information: UserAddr,
    length: u32,
) -> NtResult {
    handle_flag_arguments(class, length, FlagLength::Exactly)?;
    let mut bytes = [0u8; 2];
    information.read(&mut bytes)?;
    let flags = ObjectHandleFlagInformation::from_bytes(bytes);
    #[cfg(target_arch = "x86")]
    {
        if call
            .process()
            .update_handle(handle.raw(), |entry| flags.applied_to(entry))
        {
            Ok(STATUS_SUCCESS)
        } else {
            Err(STATUS_INVALID_HANDLE)
        }
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (call, handle, flags);
        Err(STATUS_INVALID_HANDLE)
    }
}

/// The handle tables a duplication works on — the target process's, which the duplicate goes
/// into, and the source process's, which DUPLICATE_CLOSE_SOURCE closes the source in — behind a
/// seam so the order of [`duplicate_entry`]'s steps is host-tested.
pub trait DuplicateTables {
    /// A new handle for `entry` in the target process's table, none when none can be made (a full
    /// table, or an object gone meanwhile).
    fn insert(&mut self, entry: Entry) -> Option<core::num::NonZeroU32>;
    /// Close the duplicate `handle` again, in the target process's table, releasing what it named.
    fn close_duplicate(&mut self, handle: u32);
    /// Free the source `handle`'s slot in the source process's table, what it names still
    /// counted: none when it names nothing any more.
    fn take_source(&mut self, handle: u32) -> Option<Entry>;
    /// Release what the source entry [`DuplicateTables::take_source`] took out names.
    fn release_source(&mut self, entry: Entry);
}

/// NtDuplicateObject's target-process argument.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TargetProcess {
    /// None given (a null handle): the call can only close the source.
    None,
    /// A process the call reaches (the tables' target).
    Reached,
    /// A handle the call cannot take as its target, with the reason: one naming nothing, another
    /// kind of object, a process handle without PROCESS_DUP_HANDLE, a process that has ended.
    Refused(NtStatus),
}

/// NtDuplicateObject once its source handle is found, as `entry`: a new handle naming the same
/// object in the target process, with `access` or the source's (DUPLICATE_SAME_ACCESS), inheritable
/// when the attributes say OBJ_INHERIT, written through `write` (into the caller's memory).
/// `closable` is the source handle when DUPLICATE_CLOSE_SOURCE can close it (none for a
/// pseudo-handle). From here on the option closes the source whatever the outcome, as Windows
/// 2000's does: with no target process that is the whole call (STATUS_SUCCESS;
/// STATUS_INVALID_PARAMETER without the option); a target process refused is its reason, a handle
/// that cannot be made STATUS_INSUFFICIENT_RESOURCES, and a target the write cannot reach
/// STATUS_ACCESS_VIOLATION, the new handle closed again. A source protected from close stays
/// open, the call succeeding all the same (the files fixture's capture). The source's slot is
/// freed before the duplicate is made — a duplicate into the same process takes the source's own
/// value back (slots are reused most recently freed first), as the spawn fixture's capture shows
/// Windows 2000's does — while what the source names is released only after it, so the object
/// never loses its last handle in between.
#[allow(clippy::too_many_arguments)]
pub fn duplicate_entry(
    tables: &mut impl DuplicateTables,
    entry: Entry,
    closable: Option<u32>,
    target_process: TargetProcess,
    access: u32,
    attributes: u32,
    options: u32,
    write: impl FnOnce(u32) -> Result<(), Fault>,
) -> NtResult {
    let close_source = options & DUPLICATE_CLOSE_SOURCE != 0;
    let taken = match closable {
        Some(source) if close_source && self::closable(entry).is_ok() => tables.take_source(source),
        _ => None,
    };
    let result = match target_process {
        TargetProcess::None if close_source => Ok(STATUS_SUCCESS),
        TargetProcess::None => Err(STATUS_INVALID_PARAMETER),
        TargetProcess::Refused(status) => Err(status),
        TargetProcess::Reached => {
            let access = if options & DUPLICATE_SAME_ACCESS != 0 {
                entry.access
            } else {
                access
            };
            let inherit = attributes & super::attributes::OBJ_INHERIT != 0;
            match tables.insert(Entry {
                target: entry.target,
                access,
                inherit,
                protect_from_close: false,
            }) {
                None => Err(STATUS_INSUFFICIENT_RESOURCES),
                Some(handle) => write(handle.get())
                    .map(|()| STATUS_SUCCESS)
                    .map_err(|fault| {
                        tables.close_duplicate(handle.get());
                        NtStatus::from(fault)
                    }),
            }
        }
    };
    if let Some(source) = taken {
        tables.release_source(source);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::{ObjectId, ObjectType};

    const SOURCE: u32 = 0x44;
    const NEW: u32 = 0x48;

    /// What a duplication did to the tables, in its order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Step {
        TakeSource,
        Insert,
        CloseDuplicate,
        ReleaseSource,
    }
    use Step::*;

    /// A handle table that records what the duplication did to it.
    struct Table {
        full: bool,
        inserted: Vec<Entry>,
        steps: Vec<Step>,
    }

    impl Table {
        fn new(full: bool) -> Self {
            Table {
                full,
                inserted: Vec::new(),
                steps: Vec::new(),
            }
        }
    }

    impl DuplicateTables for Table {
        fn insert(&mut self, entry: Entry) -> Option<core::num::NonZeroU32> {
            self.steps.push(Insert);
            if self.full {
                return None;
            }
            self.inserted.push(entry);
            core::num::NonZeroU32::new(NEW)
        }

        fn close_duplicate(&mut self, handle: u32) {
            assert_eq!(handle, NEW, "only the duplicate closes in the target");
            self.steps.push(CloseDuplicate);
        }

        fn take_source(&mut self, handle: u32) -> Option<Entry> {
            assert_eq!(handle, SOURCE, "only the source closes in the source");
            self.steps.push(TakeSource);
            Some(event())
        }

        fn release_source(&mut self, entry: Entry) {
            assert_eq!(entry, event(), "the source's own entry is released");
            self.steps.push(ReleaseSource);
        }
    }

    fn event() -> Entry {
        Entry::object(
            ObjectId {
                kind: ObjectType::Event,
                index: 3,
                generation: 1,
            },
            0x1F_0003,
            false,
        )
    }

    fn duplicate(
        table: &mut Table,
        target: TargetProcess,
        options: u32,
        write: Result<(), Fault>,
    ) -> NtResult {
        duplicate_entry(
            table,
            event(),
            Some(SOURCE),
            target,
            0x10_0000,
            0,
            options,
            |handle| {
                assert_eq!(handle, NEW);
                write
            },
        )
    }

    /// A duplicate names the source's object, with the access asked for or the source's, and the
    /// inheritance the attributes ask; the source is closed only when asked — its slot freed
    /// before the duplicate is made (a duplicate into its own process takes its value back), what
    /// it names released after, so the object keeps a handle throughout.
    #[test]
    fn a_duplicate_names_the_object_with_its_access() {
        let mut table = Table::new(false);
        assert_eq!(
            duplicate(&mut table, TargetProcess::Reached, 0, Ok(())),
            Ok(STATUS_SUCCESS)
        );
        assert_eq!(
            table.inserted,
            [Entry {
                access: 0x10_0000,
                ..event()
            }]
        );
        assert_eq!(table.steps, [Insert]);

        let mut table = Table::new(false);
        let result = duplicate_entry(
            &mut table,
            event(),
            Some(SOURCE),
            TargetProcess::Reached,
            0,
            super::super::attributes::OBJ_INHERIT,
            DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
            |_| Ok(()),
        );
        assert_eq!(result, Ok(STATUS_SUCCESS));
        assert_eq!(
            table.inserted,
            [Entry {
                inherit: true,
                ..event()
            }]
        );
        assert_eq!(table.steps, [TakeSource, Insert, ReleaseSource]);
    }

    /// DUPLICATE_CLOSE_SOURCE closes the source whatever the outcome once it is found: a
    /// target process naming none, a handle that cannot be made, a target handle the write cannot
    /// reach (whose new handle goes again). Without it, a failure leaves the source alone.
    #[test]
    fn close_source_closes_on_the_failure_paths_too() {
        let mut table = Table::new(false);
        let result = duplicate(
            &mut table,
            TargetProcess::Refused(STATUS_INVALID_HANDLE),
            DUPLICATE_CLOSE_SOURCE,
            Ok(()),
        );
        assert_eq!(result, Err(STATUS_INVALID_HANDLE));
        assert!(table.inserted.is_empty());
        assert_eq!(table.steps, [TakeSource, ReleaseSource]);

        let mut table = Table::new(true);
        let result = duplicate(
            &mut table,
            TargetProcess::Reached,
            DUPLICATE_CLOSE_SOURCE,
            Ok(()),
        );
        assert_eq!(result, Err(STATUS_INSUFFICIENT_RESOURCES));
        assert_eq!(table.steps, [TakeSource, Insert, ReleaseSource]);

        let mut table = Table::new(false);
        let result = duplicate(
            &mut table,
            TargetProcess::Reached,
            DUPLICATE_CLOSE_SOURCE,
            Err(Fault),
        );
        assert_eq!(result, Err(STATUS_ACCESS_VIOLATION));
        assert_eq!(
            table.steps,
            [TakeSource, Insert, CloseDuplicate, ReleaseSource]
        );

        let mut table = Table::new(true);
        assert_eq!(
            duplicate(&mut table, TargetProcess::Reached, 0, Ok(())),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(table.steps, [Insert]);
    }

    /// With no target process, closing the source is the whole call: STATUS_SUCCESS with
    /// DUPLICATE_CLOSE_SOURCE, STATUS_INVALID_PARAMETER (and the source kept) without it.
    #[test]
    fn no_target_process_only_closes_the_source() {
        let mut table = Table::new(false);
        assert_eq!(
            duplicate(
                &mut table,
                TargetProcess::None,
                DUPLICATE_CLOSE_SOURCE,
                Ok(())
            ),
            Ok(STATUS_SUCCESS)
        );
        assert!(table.inserted.is_empty());
        assert_eq!(table.steps, [TakeSource, ReleaseSource]);

        let mut table = Table::new(false);
        assert_eq!(
            duplicate(&mut table, TargetProcess::None, 0, Ok(())),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert!(table.inserted.is_empty() && table.steps.is_empty());
    }

    /// A pseudo-handle source (the current thread or process) has nothing to close.
    #[test]
    fn a_pseudo_handle_source_is_never_closed() {
        let mut table = Table::new(true);
        let result = duplicate_entry(
            &mut table,
            event(),
            None,
            TargetProcess::Reached,
            0,
            0,
            DUPLICATE_CLOSE_SOURCE,
            |_| Ok(()),
        );
        assert_eq!(result, Err(STATUS_INSUFFICIENT_RESOURCES));
        assert_eq!(table.steps, [Insert]);
    }

    /// A source protected from close stays open under DUPLICATE_CLOSE_SOURCE, and the call
    /// succeeds (the files fixture's flags block); its duplicate is not protected.
    #[test]
    fn a_protected_source_stays_open() {
        let mut table = Table::new(false);
        let protected = Entry {
            protect_from_close: true,
            ..event()
        };
        let result = duplicate_entry(
            &mut table,
            protected,
            Some(SOURCE),
            TargetProcess::Reached,
            0,
            0,
            DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
            |_| Ok(()),
        );
        assert_eq!(result, Ok(STATUS_SUCCESS));
        assert_eq!(table.steps, [Insert]);
        assert_eq!(table.inserted, [event()]);
    }

    /// A process handle's checks, in Windows' order: an entry to find, a process object, then the
    /// access. The spawn fixture's refusals map as it prints them: a null handle
    /// ERROR_INVALID_HANDLE (6), a handle without the access ERROR_ACCESS_DENIED (5), an ended
    /// process's termination ERROR_ACCESS_DENIED (5).
    #[test]
    fn process_handles_are_checked_in_windows_order() {
        let process = |access| {
            Entry::object(
                ObjectId {
                    kind: ObjectType::Process,
                    index: 2,
                    generation: 7,
                },
                access,
                false,
            )
        };
        let id = process(0).object_id().unwrap();
        assert_eq!(
            process_of_entry(None, PROCESS_VM_READ),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            process_of_entry(
                Some(Entry {
                    access: 0,
                    ..event()
                }),
                PROCESS_VM_READ
            ),
            Err(STATUS_OBJECT_TYPE_MISMATCH),
            "the kind before the access"
        );
        assert_eq!(
            process_of_entry(Some(process(PROCESS_QUERY_INFORMATION)), PROCESS_VM_READ),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            process_of_entry(
                Some(process(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)),
                PROCESS_VM_READ
            ),
            Ok(id)
        );
        assert_eq!(
            process_of_entry(
                Some(process(crate::ob::PROCESS_ALL_ACCESS)),
                PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE
            ),
            Ok(id)
        );
        assert_eq!(
            process_of_entry(Some(process(0)), 0),
            Ok(id),
            "no access asked"
        );
        for (status, error) in [
            (STATUS_INVALID_HANDLE, 6),
            (STATUS_OBJECT_TYPE_MISMATCH, 6),
            (STATUS_ACCESS_DENIED, 5),
            (STATUS_PROCESS_IS_TERMINATING, 5),
        ] {
            assert_eq!(rtl::status::dos_error(status.0), error, "{status:?}");
        }
    }

    /// The process type's generic rights: read queries and reads memory, write changes the
    /// process, execute waits on it; all, and the maximum allowed, are every right.
    #[test]
    fn generic_process_rights_map_to_the_specific_ones() {
        let read = process_access(GENERIC_READ);
        assert_eq!(
            read & (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION),
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
        );
        assert_eq!(read & (PROCESS_VM_WRITE | PROCESS_TERMINATE), 0);
        let write = process_access(GENERIC_WRITE);
        for right in [
            PROCESS_TERMINATE,
            PROCESS_CREATE_THREAD,
            PROCESS_VM_OPERATION,
            PROCESS_VM_WRITE,
            PROCESS_DUP_HANDLE,
            PROCESS_SET_INFORMATION,
        ] {
            assert_eq!(write & right, right, "{right:#x}");
        }
        assert_eq!(write & PROCESS_VM_READ, 0);
        assert_eq!(process_access(GENERIC_EXECUTE) & SYNCHRONIZE, SYNCHRONIZE);
        for all in [GENERIC_ALL, MAXIMUM_ALLOWED] {
            assert_eq!(process_access(all), crate::ob::PROCESS_ALL_ACCESS);
        }
        assert_eq!(
            process_access(PROCESS_QUERY_INFORMATION | SYNCHRONIZE),
            PROCESS_QUERY_INFORMATION | SYNCHRONIZE
        );
    }

    /// A target process the call cannot take refuses with its own reason (a handle without
    /// PROCESS_DUP_HANDLE, a process that has ended), and the source still closes when asked.
    #[test]
    fn a_refused_target_process_still_closes_the_source() {
        for reason in [STATUS_ACCESS_DENIED, STATUS_PROCESS_IS_TERMINATING] {
            let mut table = Table::new(false);
            let result = duplicate(
                &mut table,
                TargetProcess::Refused(reason),
                DUPLICATE_CLOSE_SOURCE,
                Ok(()),
            );
            assert_eq!(result, Err(reason));
            assert!(table.inserted.is_empty());
            assert_eq!(table.steps, [TakeSource, ReleaseSource]);
        }
    }

    /// The console tag: every std handle the process parameters carry has it and object handles
    /// (multiples of four) never do, so the object services can route on it; INVALID_HANDLE_VALUE
    /// is not a console handle (the bit-28 mask).
    #[test]
    fn console_handles_are_told_apart_from_object_handles() {
        use crate::user::params::{STD_ERROR, STD_INPUT, STD_OUTPUT};
        const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
        for handle in [STD_INPUT, STD_OUTPUT, STD_ERROR] {
            assert!(is_console_handle(handle), "{handle:#x}");
        }
        for handle in [4, 8, 12, 0x3C] {
            assert!(!is_console_handle(handle), "{handle:#x}");
        }
        assert!(!is_console_handle(INVALID_HANDLE_VALUE));
        assert!(!is_console_handle(0));
    }

    /// NtQueryObject and NtSetInformationObject answer ObjectHandleFlagInformation alone, the
    /// class checked before the length: a query into any buffer with room for the structure, a
    /// set from its size exactly (the files fixture's flags block).
    #[test]
    fn handle_flags_are_the_one_class_answered() {
        use FlagLength::{AtLeast, Exactly};
        assert_eq!(handle_flag_arguments(4, 2, AtLeast), Ok(()));
        assert_eq!(handle_flag_arguments(4, 8, AtLeast), Ok(()));
        assert_eq!(
            handle_flag_arguments(4, 1, AtLeast),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
        assert_eq!(handle_flag_arguments(4, 2, Exactly), Ok(()));
        for length in [0, 1, 4, 8] {
            assert_eq!(
                handle_flag_arguments(4, length, Exactly),
                Err(STATUS_INFO_LENGTH_MISMATCH),
                "{length}"
            );
        }
        for class in [0, 1, 2, 3, 5] {
            for rule in [AtLeast, Exactly] {
                assert_eq!(
                    handle_flag_arguments(class, 1, rule),
                    Err(STATUS_INVALID_INFO_CLASS)
                );
            }
        }
    }

    /// The pseudo-handles answer no flags set; any other handle is its entry's.
    #[test]
    fn pseudo_handles_answer_no_flags() {
        for handle in [CURRENT_PROCESS, CURRENT_THREAD] {
            assert_eq!(
                pseudo_handle_flags(handle).map(ObjectHandleFlagInformation::to_bytes),
                Some([0, 0])
            );
        }
        for handle in [0, 4, 0xFFFF_FFFD] {
            assert_eq!(pseudo_handle_flags(handle), None);
        }
    }

    /// An entry's attributes read as two BOOLEANs, and set from them (any nonzero byte TRUE), what
    /// the entry names and its access untouched; a protected entry is not closable.
    #[test]
    fn handle_flags_read_and_set_an_entry() {
        let entry = event();
        assert_eq!(ObjectHandleFlagInformation::of(entry).to_bytes(), [0, 0]);
        let set = ObjectHandleFlagInformation::from_bytes([1, 0x80]).applied_to(entry);
        assert_eq!(
            set,
            Entry {
                inherit: true,
                protect_from_close: true,
                ..entry
            }
        );
        assert_eq!(ObjectHandleFlagInformation::of(set).to_bytes(), [1, 1]);
        assert_eq!(closable(set), Err(STATUS_HANDLE_NOT_CLOSABLE));
        let cleared = ObjectHandleFlagInformation::from_bytes([0, 0]).applied_to(set);
        assert_eq!(cleared, entry);
        assert_eq!(closable(cleared), Ok(()));
    }
}
