//! The process services: NtOpenProcess, NtTerminateProcess, and NtQueryInformationProcess and
//! NtSetInformationProcess, the classes kernel32's process calls ask. kernel32's OpenProcess,
//! ExitProcess, TerminateProcess, GetExitCodeProcess, GlobalMemoryStatus (the virtual-memory
//! counters), Get/SetPriorityClass, SetProcessAffinityMask and SetErrorMode are Win32 code over
//! these, as on Windows 2000.
//!
//! The information services reach any process the caller holds a handle to (see
//! [`super::object::reference_process`]), with the access MSDN's Win32 calls name:
//! PROCESS_QUERY_INFORMATION to query, PROCESS_SET_INFORMATION to set. A process that has ended
//! still answers: its exit status from its object, its identity from its record (which lives as
//! long as the object). Termination reaches the calling process alone: any other handle is
//! STATUS_INVALID_HANDLE. The information's length is the class's structure's exactly, as Windows
//! 2000 checks it (STATUS_INFO_LENGTH_MISMATCH), before the handle is.

use super::call::{
    Handle,
    NtCall,
    NtResult,
    Status,
    UserAddr,
    UserPtr,
    STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER,
    STATUS_SUCCESS,
};
use super::memory::{STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS};

/// NtOpenProcess's refusals: a client id and a name both given, or neither; a thread id naming no
/// thread of the process.
const STATUS_INVALID_PARAMETER_MIX: Status = Status(0xC000_0030);
const STATUS_INVALID_CID: Status = Status(0xC000_000B);

/// PROCESSINFOCLASS: the classes F2K answers.
/// ProcessBasicInformation: PROCESS_BASIC_INFORMATION (query).
pub const PROCESS_BASIC_INFORMATION: u32 = 0;
/// ProcessVmCounters: VM_COUNTERS (query).
pub const PROCESS_VM_COUNTERS: u32 = 3;
/// ProcessDefaultHardErrorMode: the process's hard-error mode, a ULONG (query and set).
pub const PROCESS_DEFAULT_HARD_ERROR_MODE: u32 = 12;
/// ProcessPriorityClass: PROCESS_PRIORITY_CLASS (query and set).
pub const PROCESS_PRIORITY_CLASS: u32 = 18;
/// ProcessAffinityMask: the processors the process may run on, a KAFFINITY (set).
pub const PROCESS_AFFINITY_MASK: u32 = 21;

/// The classes' structures' sizes: PROCESS_BASIC_INFORMATION, VM_COUNTERS, and
/// PROCESS_PRIORITY_CLASS (Foreground, a BOOLEAN; PriorityClass, a UCHAR).
pub const PROCESS_BASIC_INFORMATION_SIZE: u32 = size_of::<ProcessBasicInformation>() as u32;
pub const VM_COUNTERS_SIZE: u32 = 44;
pub const PROCESS_PRIORITY_CLASS_SIZE: u32 = 2;

/// PROCESS_BASIC_INFORMATION: a process's exit status (STATUS_PENDING, kernel32's STILL_ACTIVE,
/// until it ends), its PEB, its affinity, its base priority, its client id and its creator's.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessBasicInformation {
    pub exit_status: u32,
    pub peb_base_address: u32,
    pub affinity_mask: u32,
    pub base_priority: i32,
    pub unique_process_id: u32,
    pub inherited_from_unique_process_id: u32,
}

const _: () = assert!(size_of::<ProcessBasicInformation>() == 24);

impl ProcessBasicInformation {
    /// The structure's bytes, as the caller's buffer receives them.
    pub fn to_bytes(self) -> [u8; PROCESS_BASIC_INFORMATION_SIZE as usize] {
        layout(&[
            self.exit_status,
            self.peb_base_address,
            self.affinity_mask,
            self.base_priority as u32,
            self.unique_process_id,
            self.inherited_from_unique_process_id,
        ])
    }
}

/// CLIENT_ID: a process's client id, and one of its threads' (zero: none).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientId {
    pub unique_process: u32,
    pub unique_thread: u32,
}

impl ClientId {
    /// The structure, from the caller's memory.
    fn read(at: UserAddr) -> Result<ClientId, Status> {
        let mut raw = [0u8; size_of::<ClientId>()];
        at.read(&mut raw)?;
        let word = |i: usize| u32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
        Ok(ClientId {
            unique_process: word(0),
            unique_thread: word(4),
        })
    }
}

/// A live process's exit status: STATUS_PENDING (kernel32's STILL_ACTIVE).
#[cfg(test)]
const STATUS_PENDING: u32 = 0x103;

/// The priority classes (PROCESS_PRIORITY_CLASS_*), and each one's base priority (Windows 2000's
/// PspPriorityTable): idle 4, normal 8, high 13, realtime 24, below normal 6, above normal 10.
pub const PRIORITY_CLASS_NORMAL: u8 = 2;
const PRIORITY_CLASS_BASES: [i8; 7] = [0, 4, 8, 13, 24, 6, 10];

/// The base priority a priority class gives the process; STATUS_INVALID_PARAMETER for a value
/// naming no class (Windows 2000 refuses past ABOVE_NORMAL, 6; F2K refuses UNKNOWN, 0, as well).
pub fn class_base_priority(class: u8) -> Result<i8, Status> {
    match PRIORITY_CLASS_BASES.get(class as usize) {
        Some(&base) if class != 0 => Ok(base),
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// Dwords as the bytes of the structure they lay out (the rest zero).
fn layout<const N: usize>(words: &[u32]) -> [u8; N] {
    let mut bytes = [0u8; N];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// VM_COUNTERS for a process reserving `reserved` bytes: its virtual size (the peak is not kept: it
/// reads as the current size); the page-fault, working-set, pool and paging-file counters zero.
pub fn vm_counters(reserved: u32) -> [u8; VM_COUNTERS_SIZE as usize] {
    layout(&[reserved, reserved])
}

/// The class's size: its structure's (none for a class F2K does not answer).
fn size_of_class(class: u32) -> Option<u32> {
    match class {
        PROCESS_BASIC_INFORMATION => Some(PROCESS_BASIC_INFORMATION_SIZE),
        PROCESS_VM_COUNTERS => Some(VM_COUNTERS_SIZE),
        PROCESS_DEFAULT_HARD_ERROR_MODE | PROCESS_AFFINITY_MASK => Some(4),
        PROCESS_PRIORITY_CLASS => Some(PROCESS_PRIORITY_CLASS_SIZE),
        _ => None,
    }
}

/// The process a handle names, when it is the calling process (the services that reach no other:
/// termination, a thread's creation).
pub(super) fn current(process: Handle) -> Result<(), Status> {
    if crate::nt::object::names_current_process(process.raw()) {
        Ok(())
    } else {
        Err(STATUS_INVALID_HANDLE)
    }
}

/// NtOpenProcess's choice of what to open, from whether the OBJECT_ATTRIBUTES name an object and
/// the CLIENT_ID given: the client id. Both, or neither, is STATUS_INVALID_PARAMETER_MIX; a name
/// alone names nothing (no process object is named): STATUS_OBJECT_NAME_NOT_FOUND.
pub fn open_by(named: bool, client_id: Option<ClientId>) -> Result<ClientId, Status> {
    match (named, client_id) {
        (false, Some(client_id)) => Ok(client_id),
        (true, None) => Err(super::attributes::STATUS_OBJECT_NAME_NOT_FOUND),
        _ => Err(STATUS_INVALID_PARAMETER_MIX),
    }
}

/// NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId): a new handle in the
/// calling process to the process whose client id `ClientId.UniqueProcess` is (and, when
/// `UniqueThread` is not zero, which has a live thread of that id: STATUS_INVALID_CID otherwise),
/// granted the access asked for — no security descriptor restricts it — its generic rights mapped
/// (see [`super::object::process_access`]), inheritable as the attributes say (OBJ_INHERIT). A
/// client id naming no process is STATUS_INVALID_PARAMETER (Windows 2000's answer: kernel32's
/// OpenProcess of id 0 prints ERROR_INVALID_PARAMETER in the spawn fixture). A process that has
/// ended opens while its object lives — a handle holds it — as its client id is not reused until
/// then. The handle's slot is probed first (STATUS_ACCESS_VIOLATION); a full table is
/// STATUS_INSUFFICIENT_RESOURCES.
pub fn open_process(
    call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    client_id: UserAddr,
) -> NtResult {
    use super::call::STATUS_ACCESS_VIOLATION;
    if slot.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    crate::user::syscall::probe_user_range(slot.addr().raw(), 4)
        .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let (named, inherit) = if attributes.is_null() {
        (false, false)
    } else {
        let mut name = [0u16; super::attributes::MAX_NAME];
        let read = super::attributes::read(attributes, &mut name)?;
        (read.length.is_some(), read.inherit())
    };
    let client_id = if client_id.is_null() {
        None
    } else {
        Some(ClientId::read(client_id)?)
    };
    let client_id = open_by(named, client_id)?;
    let access = super::object::process_access(access);
    #[cfg(target_arch = "x86")]
    {
        use super::object::STATUS_INSUFFICIENT_RESOURCES;
        let id = crate::process::pool::by_client_id(client_id.unique_process)
            .filter(|_| client_id.unique_process != 0)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        if client_id.unique_thread != 0 {
            let record = crate::process::pool::of_object(id).expect("a live process's record");
            crate::ob::directory()
                .thread_by_client_id(&record.sched, client_id.unique_thread)
                .ok_or(STATUS_INVALID_CID)?;
        }
        let process = call.process();
        let handle = crate::ob::open(process, id, access, inherit);
        if handle == 0 {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
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

/// NtTerminateProcess(ProcessHandle, ExitStatus): no handle terminates every other thread of the
/// calling process with the status, the caller running on (ExitProcess's first step on Windows
/// 2000, before the loader's shutdown); a handle naming the calling process ends it — its other
/// threads first, then the caller — with the status as its exit code. Only the calling process is
/// reachable: any other handle is STATUS_INVALID_HANDLE.
pub fn terminate_process(call: &mut NtCall, process: Handle, status: u32) -> NtResult {
    if process.raw() == 0 {
        #[cfg(target_arch = "x86")]
        crate::process::threads::terminate_other_threads(call.process(), status);
        #[cfg(not(target_arch = "x86"))]
        let _ = call;
        return Ok(STATUS_SUCCESS);
    }
    current(process)?;
    crate::user::process_exited(status)
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
    let size = match class {
        PROCESS_AFFINITY_MASK => None,
        class => size_of_class(class),
    }
    .ok_or(STATUS_INVALID_INFO_CLASS)?;
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
            PROCESS_BASIC_INFORMATION => information.write(
                &ProcessBasicInformation {
                    exit_status: target.exit_status(),
                    peb_base_address: crate::user::PEB_PAGE,
                    affinity_mask: super::thread::SYSTEM_AFFINITY,
                    base_priority: record.sched.base_priority() as i32,
                    unique_process_id: record.id(),
                    inherited_from_unique_process_id: record.parent_id(),
                }
                .to_bytes(),
            )?,
            PROCESS_VM_COUNTERS => {
                let reserved = if target.ended() {
                    0
                } else {
                    record.space().reserved_size()
                };
                information.write(&vm_counters(reserved))?
            }
            PROCESS_DEFAULT_HARD_ERROR_MODE => {
                UserPtr::<u32>::at(information.raw()).write(record.hard_error_mode())?
            }
            _ => information.write(&[0, record.priority_class()])?,
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
    let size = match class {
        PROCESS_DEFAULT_HARD_ERROR_MODE | PROCESS_PRIORITY_CLASS | PROCESS_AFFINITY_MASK => {
            size_of_class(class)
        }
        _ => None,
    }
    .ok_or(STATUS_INVALID_INFO_CLASS)?;
    if length != size {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    #[cfg(target_arch = "x86")]
    let target =
        super::object::reference_process(process.raw(), super::object::PROCESS_SET_INFORMATION)?;
    #[cfg(not(target_arch = "x86"))]
    current(process)?;
    let mut value = [0u8; 4];
    information.read(&mut value[..size as usize])?;
    match class {
        PROCESS_DEFAULT_HARD_ERROR_MODE => {
            #[cfg(target_arch = "x86")]
            target
                .record()
                .set_hard_error_mode(u32::from_le_bytes(value));
        }
        PROCESS_PRIORITY_CLASS => {
            let base = class_base_priority(value[1])?;
            #[cfg(target_arch = "x86")]
            {
                let record = target.record();
                crate::sched::idle::dispatcher().set_process_priority(&mut record.sched, base);
                record.set_priority_class(value[1]);
            }
            #[cfg(not(target_arch = "x86"))]
            let _ = base;
        }
        _ => {
            super::thread::affinity_mask(u32::from_le_bytes(value))?;
        }
    }
    let _ = call;
    Ok(STATUS_SUCCESS)
}
#[cfg(test)]
mod tests {
    use super::*;

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn the_counters_report_the_virtual_size() {
        assert_eq!(&vm_counters(0x5_0000)[..8], &[0, 0, 5, 0, 0, 0, 5, 0]);
    }

    /// PROCESS_BASIC_INFORMATION's layout: the exit status, the PEB page, the processor, the base
    /// priority, the client id and the creator's.
    #[test]
    fn the_basic_information_is_the_nt_layout() {
        let bytes = ProcessBasicInformation {
            exit_status: STATUS_PENDING,
            peb_base_address: crate::user::PEB_PAGE,
            affinity_mask: 1,
            base_priority: 13,
            unique_process_id: 8,
            inherited_from_unique_process_id: 0x2C,
        }
        .to_bytes();
        assert_eq!(bytes.len(), 24);
        assert_eq!(
            (word(&bytes, 0), word(&bytes, 4), word(&bytes, 8)),
            (0x103, crate::user::PEB_PAGE, 1)
        );
        assert_eq!(
            (word(&bytes, 12), word(&bytes, 16), word(&bytes, 20)),
            (13, 8, 0x2C)
        );
        assert_eq!(
            core::mem::offset_of!(ProcessBasicInformation, inherited_from_unique_process_id),
            20
        );
        assert_eq!(size_of::<ClientId>(), 8);
        assert_eq!(core::mem::offset_of!(ClientId, unique_thread), 4);
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
        assert_eq!(
            open_by(true, None),
            Err(super::super::attributes::STATUS_OBJECT_NAME_NOT_FOUND)
        );
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
            fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), u32> {
                let at = pointer.checked_sub(0x10000).ok_or(0xC000_0005u32)? as usize;
                bytes.copy_from_slice(self.0.get(at..at + bytes.len()).ok_or(0xC000_0005u32)?);
                Ok(())
            }

            fn write(&mut self, pointer: u32, bytes: &[u8]) -> Result<(), u32> {
                let at = pointer.checked_sub(0x10000).ok_or(0xC000_0005u32)? as usize;
                self.0
                    .get_mut(at..at + bytes.len())
                    .ok_or(0xC000_0005u32)?
                    .copy_from_slice(bytes);
                Ok(())
            }
        }
        // A slot at 0x10000, a CLIENT_ID at 0x10010, an unnamed OBJECT_ATTRIBUTES at 0x10020.
        let mut page = vec![0u8; 0x40];
        page[0x20] = 24;
        let memory = Rc::new(RefCell::new(Page(page)));
        let _installed = install(memory.clone());
        // SAFETY: a trap frame is plain dwords; all zeros is a valid one.
        let mut frame: crate::user::TrapFrame = unsafe { core::mem::zeroed() };
        let mut call = NtCall::new(&mut frame);
        let slot = UserPtr::at(0x10000);
        let (client_id, attributes) = (UserAddr(0x10010), UserAddr(0x10020));
        let access = super::super::call::STATUS_ACCESS_VIOLATION;
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

    /// Only the calling process is reachable: the host has no handle table, so the pseudo-handle
    /// alone names it; anything else is an invalid handle.
    #[test]
    fn only_the_calling_process_is_reachable() {
        assert_eq!(current(Handle(0xFFFF_FFFF)), Ok(()));
        assert_eq!(current(Handle(0x44)), Err(STATUS_INVALID_HANDLE));
        // SAFETY: a trap frame is plain dwords; all zeros is a valid one.
        let mut frame: crate::user::TrapFrame = unsafe { core::mem::zeroed() };
        let mut call = NtCall::new(&mut frame);
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
            fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), u32> {
                let at = pointer.checked_sub(0x10000).ok_or(0xC000_0005u32)? as usize;
                bytes.copy_from_slice(self.0.get(at..at + bytes.len()).ok_or(0xC000_0005u32)?);
                Ok(())
            }

            fn write(&mut self, _: u32, _: &[u8]) -> Result<(), u32> {
                Err(0xC000_0005)
            }
        }
        let memory = Rc::new(RefCell::new(Word(1u32.to_le_bytes().to_vec())));
        let _installed = install(memory.clone());
        // SAFETY: a trap frame is plain dwords; all zeros is a valid one.
        let mut frame: crate::user::TrapFrame = unsafe { core::mem::zeroed() };
        let mut call = NtCall::new(&mut frame);
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
                Err(super::super::call::STATUS_INVALID_PARAMETER),
                "{mask:#x}"
            );
        }
        assert_eq!(rtl::status::dos_error(0xC000_000D), 87);
        assert_eq!(
            set_information_process(&mut call, me, 21, UserAddr(0x20000), 4),
            Err(super::super::call::STATUS_ACCESS_VIOLATION)
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
