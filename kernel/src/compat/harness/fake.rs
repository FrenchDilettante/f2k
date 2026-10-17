//! The fake kernel: [`KernelBoundary`] host-side, standing in for the kernel under the surface.
//!
//! Wherever the kernel's own machinery runs on the host, the fake runs it rather than a model of
//! it: the per-process handle table (`sched::object`), the waitable headers and their signal
//! discipline (`sched::wait`), the open-file records and their seek arithmetic (`fs::file`), and
//! the FAT32 path lookup and file reads (`fs::fat32`) over a crafted volume carrying the hello
//! fixture's real image. The parameters page is staged the way the loader stages it, and the
//! codepage tables are the shipped codepage-1252 data.
//!
//! What only the target can do, the fake reduces to its observable minimum:
//!
//! - Waits cannot block. A wait on a signaled object is satisfied (an auto-reset event's signal is
//!   consumed); a timed wait on an unsignaled one times out with the clock advanced by the timeout,
//!   rounded up to whole ticks (nothing else runs to signal it); an infinite wait on an unsignaled
//!   object panics.
//! - Delays advance the clock by the interval in whole ticks, rounded up; a zero, past, or
//!   infinite delay leaves it.
//! - Threads never run. A created thread is a record (start, parameter, suspend count, base
//!   priority); [`FakeKernel::exit_thread`] ends one, signaling its handle.
//! - Terminating the process records the exit status; any later boundary call panics.
//! - Console writes collect per handle ([`FakeKernel::console_output`]); the target's wire (the
//!   serial line) is not modeled.
//!
//! Every boundary call that changes or depends on kernel state is logged ([`FakeKernel::calls`]),
//! so scenarios can pin how an export translates onto the boundary.

use super::boundary::{
    AddressSpace, CodePageTable, EventType, FilePosition, KernelBoundary, ProcessParameters,
};
use crate::fs::fat32::fixtures::{record, Crafted};
use crate::fs::fat32::volume::Volume;
use crate::fs::file::{OpenFile, OpenFiles};
use crate::sched::object::{HandleTable, Slot};
use crate::sched::wait::{WaitKind, Waitable};
use crate::status::{
    NtStatus, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, STATUS_SUSPEND_COUNT_EXCEEDED,
    STATUS_THREAD_IS_TERMINATING, STATUS_TIMEOUT,
};

/// Documented NTSTATUS values for the refusals the kernel's internal APIs report without a status
/// of their own (public ABI constants).
pub const STATUS_INVALID_HANDLE: NtStatus = 0xC000_0008u32 as NtStatus;
pub const STATUS_OBJECT_TYPE_MISMATCH: NtStatus = 0xC000_0024u32 as NtStatus;
pub const STATUS_INSUFFICIENT_RESOURCES: NtStatus = 0xC000_009Au32 as NtStatus;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = 0xC000_0034u32 as NtStatus;
pub const STATUS_FILE_IS_A_DIRECTORY: NtStatus = 0xC000_00BAu32 as NtStatus;
pub const STATUS_CONFLICTING_ADDRESSES: NtStatus = 0xC000_0018u32 as NtStatus;

/// NtAllocateVirtualMemory's allocation types (public constants).
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;

/// The two areas the user heap module owns: the heap region (fixed base, capped; its commits are
/// the heap services') and the CRT region (where a NULL reservation lands).
pub const HEAP_REGION_BASE: u32 = 0x0200_0000;
pub const HEAP_REGION_MAX: usize = 0x0010_0000;
pub const CRT_REGION_BASE: u32 = 0x0210_0000;

/// A NULL reservation's minimum: one 64 KiB allocation-granularity unit.
const ALLOCATION_GRANULARITY: u32 = 0x1_0000;

/// The page size commits round to.
pub const PAGE_SIZE: u32 = 0x1000;

/// The process the fake stages: a fixture that opens its own image (the hello fixture's), as the
/// loader launches it — the command line is
/// the fixture name as invoked, the image path the volume path it loaded from.
pub const COMMAND_LINE: &[u8] = b"hello";
pub const IMAGE_PATH: &[u8] = b"hello.exe";

/// The hello fixture's real image: the file the crafted volume carries as HELLO.EXE.
pub const IMAGE: &[u8] = include_bytes!("../../../../tests/hello/hello.exe");

/// The crafted volume's clusters: 4 KiB each (8 sectors), the root at 2, HELLO.EXE at 3..=9, the
/// BOOT directory at 10.
const SECTORS_PER_CLUSTER: u8 = 8;
const CLUSTER_BYTES: usize = SECTORS_PER_CLUSTER as usize * 512;
const IMAGE_FIRST_CLUSTER: u32 = 3;
const BOOT_DIRECTORY_CLUSTER: u32 = 10;

/// One logged boundary call.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Call {
    TerminateProcess(u32),
    AllocateVirtualMemory {
        base: u32,
        size: u32,
        allocation_type: u32,
    },
    Close(u32),
    CreateEvent {
        event_type: EventType,
        initial_state: bool,
    },
    SetEvent(u32),
    WaitForSingleObject {
        handle: u32,
        timeout: Option<i64>,
    },
    DelayExecution(i64),
    CreateThread {
        start: u32,
        parameter: u32,
        create_suspended: bool,
    },
    SetInformationThread {
        handle: u32,
        increment: i32,
    },
    SuspendThread(u32),
    ResumeThread(u32),
    CreateFile(Vec<u8>),
    ReadFile {
        handle: u32,
        length: u32,
    },
    QueryInformationFile(u32),
    SetInformationFile {
        handle: u32,
        position: u64,
    },
    WriteConsole {
        handle: u32,
        bytes: Vec<u8>,
    },
}

/// A created thread: never run host-side.
pub struct ThreadRecord {
    /// The thread object's waitable header (signaled at its exit).
    waitable: *mut Waitable,
    /// The thread's identifier.
    pub id: u32,
    /// Where it would enter user mode, and with what.
    pub start: u32,
    pub parameter: u32,
    /// The outstanding suspends.
    pub suspend_count: u8,
    /// The base-priority increment from the process's base.
    pub base_priority: i32,
}

/// The fake kernel (see the module docs).
pub struct FakeKernel {
    memory: AddressSpace,
    parameters: ProcessParameters,
    handles: HandleTable,
    threads: Vec<ThreadRecord>,
    next_thread_id: u32,
    files: OpenFiles,
    volume: Volume,
    ticks: u64,
    console: Vec<(u32, Vec<u8>)>,
    exit_status: Option<u32>,
    crt_reserved: u32,
    crt_committed: u32,
    calls: Vec<Call>,
}

impl FakeKernel {
    /// A fresh process: the parameters page staged, nothing else mapped, an empty handle table,
    /// the clock at tick 0, the boot volume mounted.
    pub fn new() -> FakeKernel {
        let mut kernel = FakeKernel {
            memory: AddressSpace::new(),
            parameters: ProcessParameters {
                command_line: 0,
                environment: 0,
                image_path: 0,
                image_path_room: 0,
            },
            handles: HandleTable::empty(),
            threads: Vec::new(),
            next_thread_id: 1,
            files: OpenFiles::empty(),
            volume: Volume::mount(boot_volume().device()).expect("the crafted volume mounts"),
            ticks: 0,
            console: Vec::new(),
            exit_status: None,
            crt_reserved: 0,
            crt_committed: 0,
            calls: Vec::new(),
        };
        kernel.stage_parameters(COMMAND_LINE, IMAGE_PATH);
        kernel
    }

    /// Stage the parameters page as the loader does: zeroed (the empty environment's terminator,
    /// the strings' NULs), the command line, the empty wide environment, and the image path at the
    /// kernel's offsets.
    fn stage_parameters(&mut self, command_line: &[u8], image_path: &[u8]) {
        use crate::compat::kernel32::{CMDLINE_OFFSET, ENV_OFFSET, MODULE_OFFSET, MODULE_ROOM};
        use crate::user::PARAMS_PAGE;
        assert!(command_line.len() < (ENV_OFFSET - CMDLINE_OFFSET) as usize);
        assert!(image_path.len() < MODULE_ROOM);
        self.memory.map(PARAMS_PAGE, PAGE_SIZE);
        self.memory
            .write(PARAMS_PAGE + CMDLINE_OFFSET, command_line)
            .unwrap();
        self.memory
            .write(PARAMS_PAGE + MODULE_OFFSET, image_path)
            .unwrap();
        self.parameters = ProcessParameters {
            command_line: PARAMS_PAGE + CMDLINE_OFFSET,
            environment: PARAMS_PAGE + ENV_OFFSET,
            image_path: PARAMS_PAGE + MODULE_OFFSET,
            image_path_room: MODULE_ROOM as u32,
        };
    }

    /// The boundary calls so far, in order.
    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    /// Forget the logged calls (a scenario's setup is not part of what it pins).
    pub fn clear_calls(&mut self) {
        self.calls.clear();
    }

    /// The exit status, once the process terminated.
    pub fn exit_status(&self) -> Option<u32> {
        self.exit_status
    }

    /// Everything written to the console handle `handle`, in order.
    pub fn console_output(&self, handle: u32) -> Vec<u8> {
        self.console
            .iter()
            .filter(|(written, _)| *written == handle)
            .flat_map(|(_, bytes)| bytes.iter().copied())
            .collect()
    }

    /// The clock, in ticks.
    pub fn ticks(&self) -> u64 {
        self.ticks
    }

    /// Advance the clock `ticks` ticks.
    pub fn advance(&mut self, ticks: u64) {
        self.ticks += ticks;
    }

    /// How many handles the table holds.
    pub fn live_handles(&self) -> usize {
        self.handles.live()
    }

    /// The created threads, in creation order.
    pub fn threads(&self) -> &[ThreadRecord] {
        &self.threads
    }

    /// The thread record `handle` names, if it names a thread.
    pub fn thread(&self, handle: u32) -> Option<&ThreadRecord> {
        match self.handles.lookup(handle)? {
            Slot::Thread(waitable) => self.threads.iter().find(|t| t.waitable == waitable),
            _ => None,
        }
    }

    /// End the thread `handle` names: its object signals, forever.
    pub fn exit_thread(&mut self, handle: u32) {
        let Some(Slot::Thread(waitable)) = self.handles.lookup(handle) else {
            panic!("{handle:#x} names no thread");
        };
        // SAFETY: the header was leaked at creation and lives for the test.
        unsafe { (*waitable).signal_state = 1 };
    }

    /// Whether the event `handle` names is signaled.
    pub fn event_signaled(&self, handle: u32) -> bool {
        match self.handles.lookup(handle) {
            // SAFETY: as `exit_thread`.
            Some(Slot::Event(waitable)) => unsafe { (*waitable).signal_state > 0 },
            _ => panic!("{handle:#x} names no event"),
        }
    }

    /// Whether the thread record is at its end.
    fn terminated(thread: &ThreadRecord) -> bool {
        // SAFETY: as `exit_thread`.
        unsafe { (*thread.waitable).signal_state > 0 }
    }

    /// Log a call; nothing may reach the kernel after the process terminated.
    fn log(&mut self, call: Call) {
        assert!(
            self.exit_status.is_none(),
            "{call:?} after the process terminated"
        );
        self.calls.push(call);
    }

    /// The thread record `handle` names, mutably; the refusal status otherwise.
    fn thread_mut(&mut self, handle: u32) -> Result<&mut ThreadRecord, NtStatus> {
        match self.handles.lookup(handle) {
            Some(Slot::Thread(waitable)) => Ok(self
                .threads
                .iter_mut()
                .find(|thread| thread.waitable == waitable)
                .expect("a thread slot names a record")),
            Some(_) => Err(STATUS_OBJECT_TYPE_MISMATCH),
            None => Err(STATUS_INVALID_HANDLE),
        }
    }

    /// The open-file record `handle` names; the refusal status otherwise.
    fn open_file(&mut self, handle: u32) -> Result<&mut OpenFile, NtStatus> {
        match self.handles.lookup(handle) {
            Some(Slot::File(index)) => Ok(self.files.get_mut(index)),
            Some(_) => Err(STATUS_OBJECT_TYPE_MISMATCH),
            None => Err(STATUS_INVALID_HANDLE),
        }
    }

    /// Whole ticks covering `interval` (100 ns units), rounded up.
    fn ticks_for(&self, interval: i64) -> u64 {
        (interval as u64).div_ceil(self.ke_query_time_increment() as u64)
    }
}

impl Default for FakeKernel {
    fn default() -> FakeKernel {
        FakeKernel::new()
    }
}

/// The crafted boot volume: HELLO.EXE (the fixture's image) and the empty BOOT directory in the
/// root.
fn boot_volume() -> Crafted {
    use crate::fs::fat32::dirent::ATTR_DIRECTORY;
    const ATTR_ARCHIVE: u8 = 0x20;
    let clusters = IMAGE.len().div_ceil(CLUSTER_BYTES) as u32;
    assert_eq!(IMAGE_FIRST_CLUSTER + clusters, BOOT_DIRECTORY_CLUSTER);
    let mut crafted = Crafted::new(SECTORS_PER_CLUSTER, 9);
    crafted.directory(
        2,
        &[
            record(
                b"HELLO   EXE",
                ATTR_ARCHIVE,
                IMAGE_FIRST_CLUSTER,
                IMAGE.len() as u32,
            ),
            record(b"BOOT       ", ATTR_DIRECTORY, BOOT_DIRECTORY_CLUSTER, 0),
        ],
    );
    let chain: Vec<u32> = (IMAGE_FIRST_CLUSTER..BOOT_DIRECTORY_CLUSTER).collect();
    crafted.chain(&chain);
    for (index, bytes) in IMAGE.chunks(CLUSTER_BYTES).enumerate() {
        crafted.cluster(IMAGE_FIRST_CLUSTER + index as u32, bytes);
    }
    crafted.fat(BOOT_DIRECTORY_CLUSTER, 0x0FFF_FFFF);
    crafted
}

impl KernelBoundary for FakeKernel {
    fn memory(&mut self) -> &mut AddressSpace {
        &mut self.memory
    }

    fn nt_terminate_process(&mut self, exit_status: u32) {
        self.log(Call::TerminateProcess(exit_status));
        self.exit_status = Some(exit_status);
    }

    fn process_parameters(&self) -> ProcessParameters {
        self.parameters
    }

    /// The user heap module's policy: a NULL reservation lands at the CRT region's base (whole
    /// pages, at least one allocation-granularity unit, one live reservation), and a commit inside
    /// it must extend the committed prefix contiguously. A commit inside the heap region maps the
    /// pages asked for. A reservation anywhere but NULL, and a commit anywhere else, are refused.
    fn nt_allocate_virtual_memory(
        &mut self,
        base: u32,
        size: u32,
        allocation_type: u32,
    ) -> Result<u32, NtStatus> {
        self.log(Call::AllocateVirtualMemory {
            base,
            size,
            allocation_type,
        });
        if allocation_type & MEM_RESERVE != 0 {
            if base != 0 || self.crt_reserved != 0 {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
            let reserved = size
                .max(ALLOCATION_GRANULARITY)
                .checked_next_multiple_of(PAGE_SIZE)
                .filter(|&reserved| {
                    CRT_REGION_BASE
                        .checked_add(reserved)
                        .is_some_and(|end| end <= crate::mem::paging::KERNEL_BASE)
                })
                .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
            self.crt_reserved = reserved;
            if allocation_type & MEM_COMMIT != 0 {
                self.commit_crt(size.min(reserved));
            }
            return Ok(CRT_REGION_BASE);
        }
        if allocation_type & MEM_COMMIT == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let in_crt_region = base >= CRT_REGION_BASE
            && (base as u64) < CRT_REGION_BASE as u64 + self.crt_reserved.max(1) as u64;
        if self.crt_reserved != 0 && in_crt_region {
            let offset = base - CRT_REGION_BASE;
            let end = offset
                .checked_add(size)
                .filter(|&end| end <= self.crt_reserved)
                .ok_or(STATUS_CONFLICTING_ADDRESSES)?;
            if end > self.crt_committed {
                if offset > self.crt_committed {
                    // Only a contiguous extension of the committed prefix is served.
                    return Err(STATUS_CONFLICTING_ADDRESSES);
                }
                self.commit_crt(end);
            }
            return Ok(base);
        }
        let heap_end = HEAP_REGION_BASE as u64 + HEAP_REGION_MAX as u64;
        if base < HEAP_REGION_BASE
            || base as u64 + size as u64 > heap_end
            || !base.is_multiple_of(PAGE_SIZE)
        {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        self.memory
            .map(base, size.next_multiple_of(PAGE_SIZE).max(PAGE_SIZE));
        Ok(base)
    }

    fn nt_close(&mut self, handle: u32) -> Result<(), NtStatus> {
        self.log(Call::Close(handle));
        match self.handles.close(handle) {
            Some(Slot::File(index)) => {
                let _ = self.files.release(index);
                Ok(())
            }
            Some(_) => Ok(()),
            None => Err(STATUS_INVALID_HANDLE),
        }
    }

    fn nt_create_event(
        &mut self,
        event_type: EventType,
        initial_state: bool,
    ) -> Result<u32, NtStatus> {
        self.log(Call::CreateEvent {
            event_type,
            initial_state,
        });
        if self.handles.is_full() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let kind = match event_type {
            EventType::Notification => WaitKind::NotificationEvent,
            EventType::Synchronization => WaitKind::SynchronizationEvent,
        };
        let waitable = Box::leak(Box::new(Waitable::new(kind, initial_state as i32)));
        Ok(self.handles.insert(Slot::Event(waitable)))
    }

    fn nt_set_event(&mut self, handle: u32) -> Result<(), NtStatus> {
        self.log(Call::SetEvent(handle));
        match self.handles.lookup(handle) {
            Some(Slot::Event(waitable)) => {
                // SAFETY: as `exit_thread`.
                unsafe { (*waitable).signal_state = 1 };
                Ok(())
            }
            Some(_) => Err(STATUS_OBJECT_TYPE_MISMATCH),
            None => Err(STATUS_INVALID_HANDLE),
        }
    }

    fn nt_wait_for_single_object(&mut self, handle: u32, timeout: Option<i64>) -> NtStatus {
        self.log(Call::WaitForSingleObject { handle, timeout });
        let waitable = match self.handles.lookup(handle).map(Slot::waitable) {
            Some(Some(waitable)) => waitable,
            Some(None) => return STATUS_OBJECT_TYPE_MISMATCH,
            None => return STATUS_INVALID_HANDLE,
        };
        // SAFETY: as `exit_thread`.
        let header = unsafe { &mut *waitable };
        if header.signal_state > 0 {
            if header.kind.consumes_signal() {
                header.signal_state -= 1;
            }
            return STATUS_SUCCESS;
        }
        match timeout {
            Some(interval) => {
                if interval > 0 {
                    self.ticks += self.ticks_for(interval);
                }
                STATUS_TIMEOUT
            }
            None => {
                panic!("an infinite wait on unsignaled {handle:#x}: nothing on the host signals it")
            }
        }
    }

    fn nt_delay_execution(&mut self, interval: i64) -> NtStatus {
        self.log(Call::DelayExecution(interval));
        if interval > 0 {
            self.ticks += self.ticks_for(interval);
        }
        STATUS_SUCCESS
    }

    fn nt_create_thread(
        &mut self,
        start: u32,
        parameter: u32,
        create_suspended: bool,
    ) -> Result<(u32, u32), NtStatus> {
        self.log(Call::CreateThread {
            start,
            parameter,
            create_suspended,
        });
        if self.handles.is_full() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let waitable = Box::leak(Box::new(Waitable::new(WaitKind::Thread, 0)));
        let id = self.next_thread_id;
        self.next_thread_id += 1;
        self.threads.push(ThreadRecord {
            waitable,
            id,
            start,
            parameter,
            suspend_count: create_suspended as u8,
            base_priority: 0,
        });
        Ok((self.handles.insert(Slot::Thread(waitable)), id))
    }

    fn nt_set_information_thread(&mut self, handle: u32, increment: i32) -> Result<(), NtStatus> {
        self.log(Call::SetInformationThread { handle, increment });
        self.thread_mut(handle)?.base_priority = increment;
        Ok(())
    }

    /// The kernel's suspend discipline: refused at the count's maximum or on a thread at its end.
    fn nt_suspend_thread(&mut self, handle: u32) -> Result<u32, NtStatus> {
        self.log(Call::SuspendThread(handle));
        let thread = self.thread_mut(handle)?;
        if thread.suspend_count == crate::sched::apc::MAX_SUSPEND_COUNT {
            return Err(STATUS_SUSPEND_COUNT_EXCEEDED);
        }
        if FakeKernel::terminated(thread) {
            return Err(STATUS_THREAD_IS_TERMINATING);
        }
        thread.suspend_count += 1;
        Ok(thread.suspend_count as u32 - 1)
    }

    fn nt_resume_thread(&mut self, handle: u32) -> Result<u32, NtStatus> {
        self.log(Call::ResumeThread(handle));
        let thread = self.thread_mut(handle)?;
        if FakeKernel::terminated(thread) {
            return Err(STATUS_THREAD_IS_TERMINATING);
        }
        let previous = thread.suspend_count;
        thread.suspend_count = previous.saturating_sub(1);
        Ok(previous as u32)
    }

    fn ke_query_tick_count(&self) -> u64 {
        self.ticks
    }

    fn ke_query_time_increment(&self) -> u32 {
        crate::interrupt::clock::INTERVAL_100NS
    }

    /// The kernel's open: the FAT32 lookup (root-relative, 8.3, case-folded), a directory refused,
    /// then an open-file record and a handle, refused when either is exhausted.
    fn nt_create_file(&mut self, path: &[u8]) -> Result<u32, NtStatus> {
        use crate::fs::fat32::lookup::{lookup, LookupError};
        self.log(Call::CreateFile(path.to_vec()));
        let file = lookup(&mut self.volume, path).map_err(|error| match error {
            LookupError::Invalid => crate::status::STATUS_OBJECT_NAME_INVALID,
            LookupError::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
            _ => crate::status::STATUS_FILE_CORRUPT_ERROR,
        })?;
        if file.directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        if self.handles.is_full() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let index = self.files.open(file).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(self.handles.insert(Slot::File(index)))
    }

    fn nt_read_file(&mut self, handle: u32, buffer: &mut [u8]) -> Result<u32, NtStatus> {
        self.log(Call::ReadFile {
            handle,
            length: buffer.len() as u32,
        });
        let open = *self.open_file(handle)?;
        let count = open.available(buffer.len() as u32) as usize;
        // `count` is nonzero only below the end, so the offset is within the 32-bit file.
        let read = crate::fs::fat32::read::read_at(
            &mut self.volume,
            &open.file,
            open.position as u32,
            &mut buffer[..count],
        )?;
        self.open_file(handle)?.position = open.position + read as u64;
        Ok(read as u32)
    }

    fn nt_query_information_file(&mut self, handle: u32) -> Result<FilePosition, NtStatus> {
        self.log(Call::QueryInformationFile(handle));
        let open = self.open_file(handle)?;
        Ok(FilePosition {
            position: open.position,
            size: open.file.size,
        })
    }

    fn nt_set_information_file(&mut self, handle: u32, position: u64) -> Result<(), NtStatus> {
        self.log(Call::SetInformationFile { handle, position });
        self.open_file(handle)?.position = position;
        Ok(())
    }

    fn write_console(&mut self, handle: u32, bytes: &[u8]) {
        self.log(Call::WriteConsole {
            handle,
            bytes: bytes.to_vec(),
        });
        self.console.push((handle, bytes.to_vec()));
    }

    fn ansi_code_page(&self) -> u32 {
        crate::compat::kernel32::ACP
    }

    fn oem_code_page(&self) -> u32 {
        crate::compat::kernel32::OEMCP
    }

    /// The shipped codepage-1252 tables; no other codepage has one.
    fn code_page_table(&self, code_page: u32) -> Option<CodePageTable> {
        use crate::compat::cp1252;
        (code_page == crate::compat::kernel32::ACP).then_some(CodePageTable {
            code_page,
            max_char_size: 1,
            default_char: cp1252::DEFAULT_CHAR,
            multi_byte_to_wide: &cp1252::MB_TO_WC,
            wide_to_multi_byte: cp1252::wc_to_mb,
            ctype1: cp1252::c1_flags,
            map_case: cp1252::map_case,
        })
    }
}

impl FakeKernel {
    /// Map the CRT region's prefix up to `end` bytes from its base (whole pages).
    fn commit_crt(&mut self, end: u32) {
        let end = end.next_multiple_of(PAGE_SIZE);
        if end > self.crt_committed {
            self.memory.map(CRT_REGION_BASE, end);
            self.crt_committed = end;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The staged parameters: the command line, the empty wide environment (its first unit is the
    /// terminator), and the image path, at the parameters page's offsets.
    #[test]
    fn the_parameters_page_is_staged_like_the_loader_stages_it() {
        let mut kernel = FakeKernel::new();
        let parameters = kernel.process_parameters();
        assert_eq!(parameters.command_line, crate::user::PARAMS_PAGE);
        let memory = kernel.memory();
        assert_eq!(memory.c_string(parameters.command_line), b"hello");
        assert_eq!(
            memory.wide_string(parameters.environment),
            Vec::<u16>::new()
        );
        assert_eq!(memory.u32_at(parameters.environment), 0);
        assert_eq!(memory.c_string(parameters.image_path), b"hello.exe");
    }

    /// The boot volume serves the fixture's image by its loader path, any case; the BOOT directory
    /// is refused as a file; a missing name is not found.
    #[test]
    fn the_boot_volume_serves_the_fixture_image() {
        let mut kernel = FakeKernel::new();
        let handle = kernel.nt_create_file(b"hello.exe").unwrap();
        assert_eq!(handle, 4, "the table's first handle");
        let mut image = vec![0u8; IMAGE.len() + 16];
        assert_eq!(
            kernel.nt_read_file(handle, &mut image),
            Ok(IMAGE.len() as u32)
        );
        assert_eq!(&image[..IMAGE.len()], IMAGE);
        assert_eq!(
            kernel.nt_query_information_file(handle),
            Ok(FilePosition {
                position: IMAGE.len() as u64,
                size: IMAGE.len() as u32
            })
        );
        assert!(kernel.nt_create_file(b"HELLO.EXE").is_ok());
        assert_eq!(
            kernel.nt_create_file(b"boot"),
            Err(STATUS_FILE_IS_A_DIRECTORY)
        );
        assert_eq!(
            kernel.nt_create_file(b"missing.exe"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }

    /// Handles come from the kernel's table: 4, 8, ... and a closed slot is reused first; closing
    /// a file releases its record.
    #[test]
    fn handles_follow_the_kernel_table_discipline() {
        let mut kernel = FakeKernel::new();
        let event = kernel
            .nt_create_event(EventType::Synchronization, false)
            .unwrap();
        let file = kernel.nt_create_file(b"hello.exe").unwrap();
        assert_eq!((event, file), (4, 8));
        assert_eq!(kernel.nt_close(file), Ok(()));
        assert_eq!(kernel.nt_close(file), Err(STATUS_INVALID_HANDLE));
        assert_eq!(kernel.nt_create_file(b"hello.exe"), Ok(8));
        assert_eq!(kernel.live_handles(), 2);
    }

    /// The table holds fifteen handles; the sixteenth create is refused.
    #[test]
    fn a_full_table_refuses_creates() {
        let mut kernel = FakeKernel::new();
        for _ in 1..crate::sched::object::HANDLE_SLOTS {
            kernel
                .nt_create_event(EventType::Notification, false)
                .unwrap();
        }
        assert_eq!(
            kernel.nt_create_event(EventType::Notification, false),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(
            kernel.nt_create_thread(0x0040_1000, 0, false),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
    }

    /// Waits: an auto-reset signal is consumed by the satisfied wait, a manual-reset one is not; an
    /// unsignaled timed wait times out with the clock advanced in whole ticks; a thread signals at
    /// its exit; a file names no waitable.
    #[test]
    fn waits_follow_the_signal_discipline() {
        let mut kernel = FakeKernel::new();
        let auto = kernel
            .nt_create_event(EventType::Synchronization, true)
            .unwrap();
        let manual = kernel
            .nt_create_event(EventType::Notification, true)
            .unwrap();
        assert_eq!(
            kernel.nt_wait_for_single_object(auto, Some(0)),
            STATUS_SUCCESS
        );
        assert_eq!(
            kernel.nt_wait_for_single_object(auto, Some(0)),
            STATUS_TIMEOUT
        );
        assert_eq!(
            kernel.nt_wait_for_single_object(manual, None),
            STATUS_SUCCESS
        );
        assert_eq!(
            kernel.nt_wait_for_single_object(manual, None),
            STATUS_SUCCESS
        );
        assert_eq!(
            kernel.nt_wait_for_single_object(auto, Some(1_000_000)),
            STATUS_TIMEOUT
        );
        assert_eq!(kernel.ticks(), 10);
        let (thread, _) = kernel.nt_create_thread(0x0040_1000, 7, false).unwrap();
        assert_eq!(
            kernel.nt_wait_for_single_object(thread, Some(0)),
            STATUS_TIMEOUT
        );
        kernel.exit_thread(thread);
        assert_eq!(
            kernel.nt_wait_for_single_object(thread, Some(0)),
            STATUS_SUCCESS
        );
        assert_eq!(
            kernel.nt_wait_for_single_object(thread, Some(0)),
            STATUS_SUCCESS
        );
        let file = kernel.nt_create_file(b"hello.exe").unwrap();
        assert_eq!(
            kernel.nt_wait_for_single_object(file, Some(0)),
            STATUS_OBJECT_TYPE_MISMATCH
        );
        assert_eq!(
            kernel.nt_wait_for_single_object(0x40, Some(0)),
            STATUS_INVALID_HANDLE
        );
    }

    /// The suspend discipline: previous counts back; refused at the maximum and once the thread
    /// ended; a resume never drops below zero.
    #[test]
    fn suspends_follow_the_kernel_discipline() {
        let mut kernel = FakeKernel::new();
        let (thread, _) = kernel.nt_create_thread(0x0040_1000, 0, true).unwrap();
        assert_eq!(kernel.thread(thread).unwrap().suspend_count, 1);
        assert_eq!(kernel.nt_resume_thread(thread), Ok(1));
        assert_eq!(kernel.nt_resume_thread(thread), Ok(0));
        assert_eq!(kernel.nt_suspend_thread(thread), Ok(0));
        for count in 1..crate::sched::apc::MAX_SUSPEND_COUNT {
            assert_eq!(kernel.nt_suspend_thread(thread), Ok(count as u32));
        }
        assert_eq!(
            kernel.nt_suspend_thread(thread),
            Err(STATUS_SUSPEND_COUNT_EXCEEDED)
        );
        let (ended, _) = kernel.nt_create_thread(0x0040_1000, 0, false).unwrap();
        kernel.exit_thread(ended);
        assert_eq!(
            kernel.nt_suspend_thread(ended),
            Err(STATUS_THREAD_IS_TERMINATING)
        );
        assert_eq!(
            kernel.nt_resume_thread(ended),
            Err(STATUS_THREAD_IS_TERMINATING)
        );
    }

    /// The CRT region: a NULL reservation lands at its base, rounded to whole pages and at least
    /// 64 KiB, once; commits extend the prefix contiguously and only inside the reservation.
    #[test]
    fn the_crt_region_follows_the_user_heap_policy() {
        let mut kernel = FakeKernel::new();
        assert_eq!(
            kernel.nt_allocate_virtual_memory(0, 0x10_0000, MEM_RESERVE),
            Ok(CRT_REGION_BASE)
        );
        assert!(kernel
            .nt_allocate_virtual_memory(0, 0x1000, MEM_RESERVE)
            .is_err());
        assert_eq!(
            kernel.nt_allocate_virtual_memory(CRT_REGION_BASE, 0x8000, MEM_COMMIT),
            Ok(CRT_REGION_BASE)
        );
        assert!(kernel.memory().is_mapped(CRT_REGION_BASE, 0x8000));
        assert!(kernel
            .nt_allocate_virtual_memory(CRT_REGION_BASE + 0x9000, 0x1000, MEM_COMMIT)
            .is_err());
        assert!(kernel
            .nt_allocate_virtual_memory(CRT_REGION_BASE + 0xF_F000, 0x2000, MEM_COMMIT)
            .is_err());
        let mut small = FakeKernel::new();
        assert_eq!(
            small.nt_allocate_virtual_memory(0, 1, MEM_RESERVE | MEM_COMMIT),
            Ok(CRT_REGION_BASE)
        );
        assert!(small.memory().is_mapped(CRT_REGION_BASE, PAGE_SIZE));
        assert!(small
            .nt_allocate_virtual_memory(CRT_REGION_BASE + 0xF000, 0x1000, MEM_COMMIT)
            .is_err());
    }

    /// Delays advance the clock in whole ticks, rounded up; zero and the infinite interval leave
    /// it.
    #[test]
    fn delays_advance_the_clock_in_whole_ticks() {
        let mut kernel = FakeKernel::new();
        kernel.nt_delay_execution(2_000_000);
        assert_eq!(kernel.ticks(), 20);
        kernel.nt_delay_execution(0);
        kernel.nt_delay_execution(i64::MIN);
        assert_eq!(kernel.ticks(), 20);
        kernel.nt_delay_execution(50_000);
        assert_eq!(kernel.ticks(), 21);
    }

    /// Nothing reaches the kernel once the process terminated.
    #[test]
    #[should_panic(expected = "after the process terminated")]
    fn nothing_follows_termination() {
        let mut kernel = FakeKernel::new();
        kernel.nt_terminate_process(0);
        assert_eq!(kernel.exit_status(), Some(0));
        kernel.nt_delay_execution(0);
    }
}
