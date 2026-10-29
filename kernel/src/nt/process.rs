//! The process services: NtCreateProcess, NtOpenProcess, NtTerminateProcess, and
//! NtQueryInformationProcess and NtSetInformationProcess, the classes kernel32's process calls ask.
//! kernel32's CreateProcess, OpenProcess, ExitProcess, TerminateProcess, GetExitCodeProcess,
//! GlobalMemoryStatus (the virtual-memory counters), Get/SetPriorityClass, SetProcessAffinityMask
//! and SetErrorMode are Win32 code over these, as on Windows 2000.
//!
//! The services reach any process the caller holds a handle to (see
//! [`super::object::reference_process`]), with the access MSDN's Win32 calls name:
//! PROCESS_CREATE_PROCESS to create a child of it, PROCESS_TERMINATE to end it,
//! PROCESS_QUERY_INFORMATION to query, PROCESS_SET_INFORMATION to set. A process that has ended
//! still answers: its exit status from its object, its identity from its record (which lives as
//! long as the object). The information's length is the class's structure's exactly, as Windows
//! 2000 checks it (STATUS_INFO_LENGTH_MISMATCH), before the handle is.
//!
//! NtCreateProcess makes a process with no thread, as Windows 2000's does: its address space (see
//! `exec::loader::load_section`), its handles inherited when asked, and a handle to it. kernel32's
//! CreateProcess then writes its environment and parameters into it, makes its first thread's
//! stack there, and creates that thread (NtCreateThread). F2K has no csrss to tell of the new
//! process (CsrClientCallServer's BasepCreateProcess): the kernel keeps every process itself.

pub use rtl::nt::info::{ProcessBasicInformation, ProcessPriorityClass, VmCounters};

use super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;

info_class! {
    /// The classes NtQueryInformationProcess answers (PROCESSINFOCLASS).
    pub enum QueryClass {
        /// PROCESS_BASIC_INFORMATION.
        Basic = 0,
        /// VM_COUNTERS.
        VmCounters = 3,
        /// The process's hard-error mode, a ULONG.
        DefaultHardErrorMode = 12,
        /// PROCESS_PRIORITY_CLASS.
        PriorityClass = 18,
    }
}

impl QueryClass {
    /// The length the class's information must have: its structure's.
    pub fn size(self) -> u32 {
        (match self {
            QueryClass::Basic => size_of::<ProcessBasicInformation>(),
            QueryClass::VmCounters => size_of::<VmCounters>(),
            QueryClass::DefaultHardErrorMode => size_of::<u32>(),
            QueryClass::PriorityClass => size_of::<ProcessPriorityClass>(),
        }) as u32
    }
}

info_class! {
    /// The classes NtSetInformationProcess takes (PROCESSINFOCLASS).
    pub enum SetClass {
        /// The process's hard-error mode, a ULONG.
        DefaultHardErrorMode = 12,
        /// PROCESS_PRIORITY_CLASS.
        PriorityClass = 18,
        /// The processors the process may run on, a KAFFINITY.
        AffinityMask = 21,
    }
}

impl SetClass {
    /// The length the class's information must have: its structure's.
    pub fn size(self) -> u32 {
        (match self {
            SetClass::DefaultHardErrorMode | SetClass::AffinityMask => size_of::<u32>(),
            SetClass::PriorityClass => size_of::<ProcessPriorityClass>(),
        }) as u32
    }
}

/// CLIENT_ID, as the caller's memory holds it: a process's client id, and one of its threads'
/// (zero: none).
pub type ClientId = rtl::nt::ClientId<u32>;

/// The priority classes (PROCESS_PRIORITY_CLASS_*), and each one's base priority (Windows 2000's
/// PspPriorityTable): idle 4, normal 8, high 13, realtime 24, below normal 6, above normal 10.
pub const PRIORITY_CLASS_NORMAL: u8 = 2;
const PRIORITY_CLASS_BASES: [i8; 7] = [0, 4, 8, 13, 24, 6, 10];

/// The base priority a priority class gives the process; STATUS_INVALID_PARAMETER for a value
/// naming no class (Windows 2000 refuses past ABOVE_NORMAL, 6; F2K refuses UNKNOWN, 0, as well).
pub fn class_base_priority(class: u8) -> Result<i8, NtStatus> {
    match PRIORITY_CLASS_BASES.get(class as usize) {
        Some(&base) if class != 0 => Ok(base),
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// VM_COUNTERS for a process reserving `reserved` bytes: its virtual size (the peak is not kept: it
/// reads as the current size); the page-fault, working-set, pool and paging-file counters zero.
pub fn vm_counters(reserved: u32) -> VmCounters {
    VmCounters {
        peak_virtual_size: reserved,
        virtual_size: reserved,
        ..Default::default()
    }
}

/// The process a handle names, when it is the calling process: host builds have no other process
/// to reach.
#[cfg(not(target_arch = "x86"))]
pub(super) fn current(process: Handle) -> Result<(), NtStatus> {
    if crate::nt::object::names_current_process(process.raw()) {
        Ok(())
    } else {
        Err(STATUS_INVALID_HANDLE)
    }
}

/// NtOpenProcess's choice of what to open, from whether the OBJECT_ATTRIBUTES name an object and
/// the CLIENT_ID given: the client id. Both, or neither, is STATUS_INVALID_PARAMETER_MIX; a name
/// alone names nothing (no process object is named): STATUS_OBJECT_NAME_NOT_FOUND.
pub fn open_by(named: bool, client_id: Option<ClientId>) -> Result<ClientId, NtStatus> {
    match (named, client_id) {
        (false, Some(client_id)) => Ok(client_id),
        (true, None) => Err(STATUS_OBJECT_NAME_NOT_FOUND),
        _ => Err(STATUS_INVALID_PARAMETER_MIX),
    }
}

/// NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId): a new handle in the
/// calling process to the process whose client id `ClientId.UniqueProcess` is (and, when
/// `UniqueThread` is not zero, which has a live thread of that id: STATUS_INVALID_CID otherwise),
/// granted the access asked for — no security descriptor restricts it — its generic rights mapped
/// (see [`super::object::process_access`]), inheritable as the attributes say (OBJ_INHERIT). A
/// client id naming no process is STATUS_INVALID_PARAMETER (Windows 2000's answer: kernel32's
/// OpenProcess of id 0 prints ERROR_INVALID_PARAMETER in the spawn fixture), and so is the id of a
/// process that has ended, even while a handle holds its object: its id left the client id table
/// with its last thread (see [`crate::process::pool::by_client_id`]). The handle's slot is probed
/// first (STATUS_ACCESS_VIOLATION); a full table is STATUS_INSUFFICIENT_RESOURCES.
pub fn open_process(
    call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    client_id: UserAddr,
) -> NtResult {
    if slot.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    crate::user::syscall::probe_user_range(slot.addr().raw(), 4)
        .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let (named, inherit) = if attributes.is_null() {
        (false, false)
    } else {
        let mut name = super::attributes::Name::new();
        let read = super::attributes::read(attributes, &mut name)?;
        (read.name.is_some(), read.inherit())
    };
    let client_id = if client_id.is_null() {
        None
    } else {
        Some(client_id.cast::<ClientId>().read()?)
    };
    let client_id = open_by(named, client_id)?;
    let access = super::object::process_access(access);
    #[cfg(target_arch = "x86")]
    {
        let id = crate::process::pool::by_client_id(client_id.unique_process)
            .filter(|_| client_id.unique_process != 0)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        if client_id.unique_thread != 0 {
            let record = crate::process::pool::of_object(id).expect("a live process's record");
            let owner = record.sched_ptr().cast_const();
            crate::ob::lock(call.passive())
                .thread_by_client_id(owner, client_id.unique_thread)
                .ok_or(STATUS_INVALID_CID)?;
        }
        let process = call.process();
        let handle = crate::ob::open(process, id, access, inherit)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?
            .get();
        if slot.write(handle).is_err() {
            process.close_handle(handle);
            return Err(STATUS_ACCESS_VIOLATION);
        }
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        // Host builds have no process table: no client id names a process.
        let _ = (call, access, inherit, client_id, STATUS_INVALID_CID);
        Err(STATUS_INVALID_PARAMETER)
    }
}

/// The arguments NtCreateProcess checks before it reaches an object, in Windows 2000's order: the
/// handle's slot probed (`slot_ok`: STATUS_ACCESS_VIOLATION otherwise), a parent process given
/// (STATUS_INVALID_PARAMETER: only the system's own first process has none), and a section given —
/// none asks for the parent's address space copied, which F2K does not make
/// (STATUS_NOT_IMPLEMENTED).
pub fn create_arguments(slot_ok: bool, parent: Handle, section: Handle) -> Result<(), NtStatus> {
    if !slot_ok {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if parent.raw() == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if section.raw() == 0 {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    Ok(())
}

/// NtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess,
/// InheritObjectTable, SectionHandle, DebugPort, ExceptionPort): a new process, with no thread,
/// whose image is the image section `SectionHandle` names (granting SECTION_MAP_EXECUTE: see
/// [`super::section::image_segment_of`]; a data section is STATUS_SECTION_NOT_IMAGE), child of the
/// process `ParentProcess` names (granting PROCESS_CREATE_PROCESS): its address space as every
/// process's starts (see `exec::loader::load_section`), its parent's client id recorded
/// (ProcessBasicInformation's InheritedFromUniqueProcessId), its parent's hard-error mode taken
/// (CreateProcess's CREATE_DEFAULT_ERROR_MODE is kernel32's to undo); with InheritObjectTable (a
/// BOOLEAN), every inheritable handle of the parent's at its own value in the child's table (see
/// [`crate::process::Process::inherit_handles`]). With it or without it, the parent's inheritable
/// console handles, at their values, as the console server hands them to every process sharing the
/// console (the spawn fixture's inheritflags block: an inheritable CONOUT$ handle reaches a child
/// created without bInheritHandles; a handle not inheritable does not). Named
/// `<image's file name, without its extension>` in its end report. A handle to it with
/// DesiredAccess (its generic rights mapped, see [`super::object::process_access`]), inheritable as
/// the attributes say (OBJ_INHERIT; a name is not looked at: process objects have none), goes into
/// ProcessHandle. The ports have no meaning here (F2K has no LPC ports): they are not looked at.
///
/// The argument checks first (see [`create_arguments`]), then the parent's handle and the
/// section's (their refusals; a parent that has ended or is ending is
/// STATUS_PROCESS_IS_TERMINATING), a full handle table (STATUS_INSUFFICIENT_RESOURCES), then the
/// process's creation's (see [`crate::exec::loader::load_section`]): every refusal leaves nothing
/// behind. The creation is one critical region: the caller cannot end half-way through it.
#[allow(clippy::too_many_arguments)]
pub fn create_process(
    call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    parent: Handle,
    inherit_object_table: bool,
    section: Handle,
    debug_port: Handle,
    exception_port: Handle,
) -> NtResult {
    let slot_ok =
        !slot.is_null() && crate::user::syscall::probe_user_range(slot.addr().raw(), 4).is_ok();
    create_arguments(slot_ok, parent, section)?;
    let _ = (debug_port, exception_port);
    #[cfg(target_arch = "x86")]
    {
        use super::object::{reference_process, PROCESS_CREATE_PROCESS};
        let parent = reference_process(parent.raw(), PROCESS_CREATE_PROCESS)?;
        if parent.ended() || parent.record().terminating() {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        // The section, and through it the image segment, is held for the call.
        let (_section, segment) = super::section::image_segment_of(section.raw())?;
        let inherit = if attributes.is_null() {
            false
        } else {
            let mut name = super::attributes::Name::new();
            super::attributes::read(attributes, &mut name)?.inherit()
        };
        if call.process().handles_full() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        crate::process::threads::critical_region(|| {
            let name = image_name(segment);
            let creator = parent.record();
            let child = crate::exec::loader::load_section(segment, name, creator.id())?;
            child.set_hard_error_mode(creator.hard_error_mode());
            child.set_console(creator.console().inherited());
            if inherit_object_table {
                child.inherit_handles(creator);
            }
            let process = call.process();
            let Some(handle) = crate::ob::open(
                process,
                child.object(),
                super::object::process_access(access),
                inherit,
            ) else {
                child.discard();
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            };
            let handle = handle.get();
            // Probed above; a slot that went away meanwhile takes the process back: its one handle
            // closes, which ends a process that never had a thread.
            if slot.write(handle).is_err() {
                process.close_handle(handle);
                return Err(STATUS_ACCESS_VIOLATION);
            }
            Ok(STATUS_SUCCESS)
        })
    }
    #[cfg(not(target_arch = "x86"))]
    {
        // Host builds have no process to make one of.
        let _ = (call, access, attributes, inherit_object_table);
        Err(STATUS_INVALID_HANDLE)
    }
}

/// The name a process made from the image segment `segment` names reports by: its file's name in
/// its directory, without its extension ("?" when the directory cannot be read).
#[cfg(target_arch = "x86")]
fn image_name(segment: crate::ob::SegmentId) -> crate::process::ProcessName {
    let record = crate::ob::locked(|directory| {
        let file_object = directory.segment(segment)?.file_object;
        directory.file(file_object).map(|object| object.record)
    });
    // The entry's name is read off the disk, with the directory released.
    let file = record.map(crate::fs::io::file_at);
    let mut name = [0u8; crate::fs::fat32::path::MAX_NAME];
    match file.and_then(|file| crate::fs::io::entry_name(&file, &mut name)) {
        Some(length) => crate::process::ProcessName::of_file(&name[..length]),
        None => crate::process::ProcessName::new(b"?"),
    }
}

/// NtTerminateProcess(ProcessHandle, ExitStatus): no handle terminates every other thread of the
/// calling process with the status, the caller running on (ExitProcess's first step on Windows
/// 2000, before the loader's shutdown); a handle naming the calling process ends it — its other
/// threads first, then the caller — with the status as its exit code; a handle naming another
/// process ends that one — every thread of it, then the process with the status as its exit code
/// (see [`crate::process::threads::terminate_process`]: a process that never reached user mode
/// ends with 0) — and returns. The handle must grant PROCESS_TERMINATE (see
/// [`super::object::reference_process`]: STATUS_ACCESS_DENIED otherwise); a process that has ended,
/// or whose end is under way, is STATUS_PROCESS_IS_TERMINATING (kernel32's TerminateProcess
/// prints ERROR_ACCESS_DENIED for it in the spawn fixture).
pub fn terminate_process(call: &mut NtCall, process: Handle, status: u32) -> NtResult {
    if process.raw() == 0 {
        #[cfg(target_arch = "x86")]
        crate::process::threads::terminate_other_threads(call.process(), status);
        #[cfg(not(target_arch = "x86"))]
        let _ = call;
        return Ok(STATUS_SUCCESS);
    }
    #[cfg(target_arch = "x86")]
    {
        use super::object::{reference_process, PROCESS_TERMINATE};
        let _ = call;
        let target = reference_process(process.raw(), PROCESS_TERMINATE)?;
        if target.is_current() {
            drop(target);
            crate::user::process_exited(status)
        }
        if target.ended() || target.record().terminating() {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        crate::process::threads::terminate_process(target.record(), status);
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        // Host builds have no process table: the pseudo-handle alone names a process.
        current(process)?;
        crate::user::process_exited(status)
    }
}

/// NtQueryInformationProcess: the basic information (the exit status from the process's object,
/// its PEB — every process's is at the same page — its client id and its creator's), the
/// virtual-memory counters (an ended process's address space is gone: zero), the hard-error mode
/// and the priority class (never foreground: no window has the focus), of any process whose handle
/// grants PROCESS_QUERY_INFORMATION. STATUS_INVALID_INFO_CLASS for the classes F2K does not answer.
pub fn query_information_process(
    call: &mut NtCall,
    process: Handle,
    class: u32,
    information: UserAddr,
    length: u32,
    return_length: UserPtr<u32>,
) -> NtResult {
    let class = QueryClass::try_from(class)?;
    let size = class.size();
    if length != size {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    #[cfg(target_arch = "x86")]
    {
        let _ = call;
        let target = super::object::reference_process(
            process.raw(),
            super::object::PROCESS_QUERY_INFORMATION,
        )?;
        let record = target.record();
        match class {
            QueryClass::Basic => information.cast().write(ProcessBasicInformation {
                exit_status: target.exit_status(),
                peb_base_address: crate::user::PEB_PAGE,
                affinity_mask: super::thread::SYSTEM_AFFINITY,
                base_priority: record.base_priority() as i32,
                unique_process_id: record.id(),
                inherited_from_unique_process_id: record.parent_id(),
            })?,
            QueryClass::VmCounters => {
                let reserved = if target.ended() {
                    0
                } else {
                    record.with_space(|space| space.reserved_size())
                };
                information.cast().write(vm_counters(reserved))?
            }
            QueryClass::DefaultHardErrorMode => {
                information.cast().write(record.hard_error_mode())?
            }
            QueryClass::PriorityClass => information.cast().write(ProcessPriorityClass {
                foreground: 0,
                priority_class: record.priority_class(),
            })?,
        }
    }
    #[cfg(not(target_arch = "x86"))]
    {
        // Host builds have no process: the pseudo-handle alone is checked.
        let _ = (call, information);
        current(process)?;
    }
    return_length.write_optional(size)?;
    Ok(STATUS_SUCCESS)
}

/// NtSetInformationProcess: the hard-error mode (kept for its round trip: no hard-error or fault
/// dialog exists to suppress), the priority class (every thread's priority moves with the process's
/// base, their increments kept; the realtime class needs no privilege here) and the affinity (a
/// non-empty subset of the one processor: nothing to change), of any process whose handle grants
/// PROCESS_SET_INFORMATION. The handle is checked first, then the value.
/// STATUS_INVALID_INFO_CLASS for the classes F2K does not answer.
pub fn set_information_process(
    call: &mut NtCall,
    process: Handle,
    class: u32,
    information: UserAddr,
    length: u32,
) -> NtResult {
    let class = SetClass::try_from(class)?;
    if length != class.size() {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    #[cfg(target_arch = "x86")]
    let target =
        super::object::reference_process(process.raw(), super::object::PROCESS_SET_INFORMATION)?;
    #[cfg(not(target_arch = "x86"))]
    current(process)?;
    match class {
        SetClass::DefaultHardErrorMode => {
            let mode = information.cast::<u32>().read()?;
            #[cfg(target_arch = "x86")]
            target.record().set_hard_error_mode(mode);
            #[cfg(not(target_arch = "x86"))]
            let _ = mode;
        }
        SetClass::PriorityClass => {
            let class = information.cast::<ProcessPriorityClass>().read()?;
            let base = class_base_priority(class.priority_class)?;
            #[cfg(target_arch = "x86")]
            {
                let record = target.record();
                crate::sched::DISPATCHER
                    .get(&mut call.passive().raise::<crate::level::Dispatch>())
                    .set_process_priority(record.sched_ptr(), base);
                record.set_priority_class(class.priority_class);
            }
            #[cfg(not(target_arch = "x86"))]
            let _ = base;
        }
        SetClass::AffinityMask => {
            super::thread::affinity_mask(information.cast::<u32>().read()?)?;
        }
    }
    let _ = call;
    Ok(STATUS_SUCCESS)
}
#[cfg(test)]
mod tests {
    use rtl::pod::Pod;

    use super::*;

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn the_counters_report_the_virtual_size() {
        assert_eq!(
            &vm_counters(0x5_0000).as_bytes()[..8],
            &[0, 0, 5, 0, 0, 0, 5, 0]
        );
    }

    /// PROCESS_BASIC_INFORMATION's layout: the exit status, the PEB page, the processor, the base
    /// priority, the client id and the creator's.
    #[test]
    fn the_basic_information_is_the_nt_layout() {
        let information = ProcessBasicInformation {
            exit_status: STATUS_PENDING.0,
            peb_base_address: crate::user::PEB_PAGE,
            affinity_mask: 1,
            base_priority: 13,
            unique_process_id: 8,
            inherited_from_unique_process_id: 0x2C,
        };
        let bytes = information.as_bytes();
        assert_eq!(bytes.len(), 24);
        assert_eq!(
            (word(bytes, 0), word(bytes, 4), word(bytes, 8)),
            (0x103, crate::user::PEB_PAGE, 1)
        );
        assert_eq!(
            (word(bytes, 12), word(bytes, 16), word(bytes, 20)),
            (13, 8, 0x2C)
        );
        assert_eq!(
            core::mem::offset_of!(ProcessBasicInformation, inherited_from_unique_process_id),
            20
        );
    }

    /// NtOpenProcess opens by client id alone: a name besides it, or neither, is a parameter mix
    /// (ERROR_INVALID_PARAMETER), a name alone names no process (ERROR_FILE_NOT_FOUND).
    #[test]
    fn a_process_opens_by_its_client_id() {
        let id = ClientId {
            unique_process: 8,
            unique_thread: 0,
        };
        assert_eq!(open_by(false, Some(id)), Ok(id));
        assert_eq!(open_by(true, Some(id)), Err(STATUS_INVALID_PARAMETER_MIX));
        assert_eq!(open_by(false, None), Err(STATUS_INVALID_PARAMETER_MIX));
        assert_eq!(open_by(true, None), Err(STATUS_OBJECT_NAME_NOT_FOUND));
        assert_eq!(rtl::status::dos_error(STATUS_INVALID_PARAMETER_MIX.0), 87);
        assert_eq!(rtl::status::dos_error(STATUS_INVALID_CID.0), 87);
        assert_eq!(rtl::status::dos_error(STATUS_INVALID_PARAMETER.0), 87);
    }

    /// NtOpenProcess checks its slot first, then reads its attributes and client id: a null slot
    /// or unreadable arguments are access violations; on the host no client id names a process
    /// (the spawn fixture's OpenProcess of id 0: ERROR_INVALID_PARAMETER).
    #[test]
    fn open_process_checks_its_arguments_in_order() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use crate::user::syscall::host::{install, UserMemory};
        struct Page(Vec<u8>);
        impl UserMemory for Page {
            fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), NtStatus> {
                let at = pointer
                    .checked_sub(0x10000)
                    .ok_or(STATUS_ACCESS_VIOLATION)? as usize;
                bytes.copy_from_slice(
                    self.0
                        .get(at..at + bytes.len())
                        .ok_or(STATUS_ACCESS_VIOLATION)?,
                );
                Ok(())
            }

            fn write(&mut self, pointer: u32, bytes: &[u8]) -> Result<(), NtStatus> {
                let at = pointer
                    .checked_sub(0x10000)
                    .ok_or(STATUS_ACCESS_VIOLATION)? as usize;
                self.0
                    .get_mut(at..at + bytes.len())
                    .ok_or(STATUS_ACCESS_VIOLATION)?
                    .copy_from_slice(bytes);
                Ok(())
            }
        }
        // A slot at 0x10000, a CLIENT_ID at 0x10010, an unnamed OBJECT_ATTRIBUTES at 0x10020.
        let mut page = vec![0u8; 0x40];
        page[0x20] = 24;
        let memory = Rc::new(RefCell::new(Page(page)));
        let _installed = install(memory.clone());
        let mut frame = crate::user::TrapFrame::default();
        let mut passive = crate::level::passive_for_test();
        let mut call = NtCall::new(&mut frame, &mut passive);
        let slot = UserPtr::at(0x10000);
        let (client_id, attributes) = (UserAddr(0x10010), UserAddr(0x10020));
        let access = STATUS_ACCESS_VIOLATION;
        assert_eq!(
            open_process(&mut call, UserPtr::at(0), 0x400, attributes, client_id),
            Err(access)
        );
        assert_eq!(
            open_process(&mut call, slot, 0x400, attributes, UserAddr(0x20000)),
            Err(access)
        );
        assert_eq!(
            open_process(&mut call, slot, 0x400, UserAddr(0), UserAddr(0)),
            Err(STATUS_INVALID_PARAMETER_MIX)
        );
        assert_eq!(
            open_process(&mut call, slot, 0x400, attributes, client_id),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    /// NtCreateProcess's own checks, in order: the handle's slot, then a parent (required: only
    /// the system's first process has none), then a section (none asks for a fork, not made). On
    /// the host, past them, no handle names anything.
    #[test]
    fn create_process_checks_its_arguments_in_order() {
        let (parent, section) = (Handle(0xFFFF_FFFF), Handle(0x44));
        assert_eq!(
            create_arguments(false, Handle(0), Handle(0)),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(
            create_arguments(true, Handle(0), section),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            create_arguments(true, parent, Handle(0)),
            Err(STATUS_NOT_IMPLEMENTED)
        );
        assert_eq!(create_arguments(true, parent, section), Ok(()));
        assert_eq!(rtl::status::dos_error(STATUS_NOT_IMPLEMENTED.0), 1);
        let mut frame = crate::user::TrapFrame::default();
        let mut passive = crate::level::passive_for_test();
        let mut call = NtCall::new(&mut frame, &mut passive);
        assert_eq!(
            create_process(
                &mut call,
                UserPtr::at(0),
                0x1F_0FFF,
                UserAddr(0),
                parent,
                true,
                section,
                Handle(0),
                Handle(0)
            ),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }

    /// Only the calling process is reachable: the host has no handle table, so the pseudo-handle
    /// alone names it; anything else is an invalid handle.
    #[test]
    fn only_the_calling_process_is_reachable() {
        assert_eq!(current(Handle(0xFFFF_FFFF)), Ok(()));
        assert_eq!(current(Handle(0x44)), Err(STATUS_INVALID_HANDLE));
        let mut frame = crate::user::TrapFrame::default();
        let mut passive = crate::level::passive_for_test();
        let mut call = NtCall::new(&mut frame, &mut passive);
        assert_eq!(
            terminate_process(&mut call, Handle(0x44), 3),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    /// The affinity: the class's exact length, the calling process alone, and a non-empty subset of
    /// the one processor (SetProcessAffinityMask's ERROR_INVALID_PARAMETER and
    /// ERROR_INVALID_HANDLE).
    #[test]
    fn the_affinity_is_the_one_processor() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use crate::user::syscall::host::{install, UserMemory};
        struct Word(Vec<u8>);
        impl UserMemory for Word {
            fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), NtStatus> {
                let at = pointer
                    .checked_sub(0x10000)
                    .ok_or(STATUS_ACCESS_VIOLATION)? as usize;
                bytes.copy_from_slice(
                    self.0
                        .get(at..at + bytes.len())
                        .ok_or(STATUS_ACCESS_VIOLATION)?,
                );
                Ok(())
            }

            fn write(&mut self, _: u32, _: &[u8]) -> Result<(), NtStatus> {
                Err(STATUS_ACCESS_VIOLATION)
            }
        }
        let memory = Rc::new(RefCell::new(Word(1u32.to_le_bytes().to_vec())));
        let _installed = install(memory.clone());
        let mut frame = crate::user::TrapFrame::default();
        let mut passive = crate::level::passive_for_test();
        let mut call = NtCall::new(&mut frame, &mut passive);
        let me = Handle(0xFFFF_FFFF);
        let at = UserAddr(0x10000);
        assert_eq!(
            set_information_process(&mut call, me, 21, at, 4),
            Ok(STATUS_SUCCESS)
        );
        assert_eq!(
            set_information_process(&mut call, me, 21, at, 8),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
        assert_eq!(
            set_information_process(&mut call, me, 13, at, 4),
            Err(STATUS_INVALID_INFO_CLASS)
        );
        assert_eq!(
            set_information_process(&mut call, Handle(0x44), 21, at, 4),
            Err(STATUS_INVALID_HANDLE)
        );
        for mask in [0u32, 2, 3] {
            memory.borrow_mut().0 = mask.to_le_bytes().to_vec();
            assert_eq!(
                set_information_process(&mut call, me, 21, at, 4),
                Err(STATUS_INVALID_PARAMETER),
                "{mask:#x}"
            );
        }
        assert_eq!(rtl::status::dos_error(0xC000_000D), 87);
        assert_eq!(
            set_information_process(&mut call, me, 21, UserAddr(0x20000), 4),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }

    /// The classes' base priorities: the threads fixture's priority block moves the process to the
    /// high class (13) and back to normal (8).
    #[test]
    fn priority_classes_give_windows_2000s_bases() {
        let bases: Vec<_> = (1..=6)
            .map(|class| class_base_priority(class).unwrap())
            .collect();
        assert_eq!(bases, [4, 8, 13, 24, 6, 10]);
        assert_eq!(class_base_priority(PRIORITY_CLASS_NORMAL), Ok(8));
        assert_eq!(class_base_priority(0), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(class_base_priority(7), Err(STATUS_INVALID_PARAMETER));
    }
}
