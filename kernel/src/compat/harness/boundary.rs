//! The kernel boundary: the kernel-side operations the kernel32 surface performs, as one trait.
//!
//! Each operation is named after the public interface it corresponds to (`Nt*` system services,
//! the `Ke*` clock queries, the PEB's process parameters) and models exactly what a current
//! service asks of the kernel — nothing more. A user-mode implementation of the exports is written
//! against [`KernelBoundary`]; host-side, [`super::fake::FakeKernel`] stands in for the kernel.
//!
//! The boundary's statuses are NTSTATUS values. The services collapse every failure to their own
//! failure return (FALSE, NULL, INVALID_HANDLE_VALUE, (DWORD)-1), so which failure status a refusal
//! carries is not observable through the surface; only success versus failure is.
//!
//! The operations, with the services they serve:
//!
//! | Operation | Served services |
//! |---|---|
//! | [`memory`](KernelBoundary::memory) | every service that reads or writes caller memory |
//! | [`nt_terminate_process`](KernelBoundary::nt_terminate_process) | ExitProcess |
//! | [`process_parameters`](KernelBoundary::process_parameters) | GetCommandLineA, GetModuleFileNameA, GetEnvironmentStringsW |
//! | [`nt_allocate_virtual_memory`](KernelBoundary::nt_allocate_virtual_memory) | HeapAlloc, HeapReAlloc (region commits), VirtualAlloc |
//! | [`nt_close`](KernelBoundary::nt_close) | CloseHandle |
//! | [`nt_create_event`](KernelBoundary::nt_create_event) | CreateEventA |
//! | [`nt_set_event`](KernelBoundary::nt_set_event) | SetEvent |
//! | [`nt_wait_for_single_object`](KernelBoundary::nt_wait_for_single_object) | WaitForSingleObject |
//! | [`nt_delay_execution`](KernelBoundary::nt_delay_execution) | Sleep |
//! | [`nt_create_thread`](KernelBoundary::nt_create_thread) | CreateThread |
//! | [`nt_set_information_thread`](KernelBoundary::nt_set_information_thread) | SetThreadPriority |
//! | [`nt_suspend_thread`](KernelBoundary::nt_suspend_thread) | SuspendThread |
//! | [`nt_resume_thread`](KernelBoundary::nt_resume_thread) | ResumeThread |
//! | [`ke_query_tick_count`](KernelBoundary::ke_query_tick_count), [`ke_query_time_increment`](KernelBoundary::ke_query_time_increment) | GetTickCount |
//! | [`nt_create_file`](KernelBoundary::nt_create_file) | CreateFileA |
//! | [`nt_read_file`](KernelBoundary::nt_read_file) | ReadFile |
//! | [`nt_query_information_file`](KernelBoundary::nt_query_information_file), [`nt_set_information_file`](KernelBoundary::nt_set_information_file) | SetFilePointer |
//! | [`write_console`](KernelBoundary::write_console) | WriteFile (console handles) |
//! | [`ansi_code_page`](KernelBoundary::ansi_code_page), [`oem_code_page`](KernelBoundary::oem_code_page), [`code_page_table`](KernelBoundary::code_page_table) | GetACP, GetOEMCP, GetCPInfo, MultiByteToWideChar, WideCharToMultiByte, LCMapStringW, GetStringTypeW |
//!
//! Services with no row answer without the kernel: replayed constants (GetVersion,
//! GetStartupInfoA, GetStdHandle, GetFileType, GetCurrentProcess), identities and success floors
//! (SetHandleCount, FlushFileBuffers, FreeEnvironmentStrings*, VirtualFree, HeapCreate,
//! HeapDestroy, HeapFree), and the never-called floors.

use crate::status::NtStatus;

/// A fault: an access to caller memory nothing is mapped at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    /// The first unmapped byte the access touched.
    pub address: u32,
}

/// One contiguous mapped range of the address space.
struct Mapping {
    base: u32,
    bytes: Vec<u8>,
}

impl Mapping {
    fn end(&self) -> u64 {
        self.base as u64 + self.bytes.len() as u64
    }
}

/// The calling process's address space, host-side: 32-bit addresses over sparse zero-initialized
/// mappings. Not a kernel call on the real system (a user-mode implementation touches its own
/// memory directly); host-side it is how both the implementation and the scenarios reach it.
#[derive(Default)]
pub struct AddressSpace {
    mappings: Vec<Mapping>,
}

impl AddressSpace {
    /// An empty address space: nothing mapped.
    pub fn new() -> AddressSpace {
        AddressSpace::default()
    }

    /// Map `length` zeroed bytes at `base`. A range that starts inside (or right at the end of) an
    /// existing mapping extends it; already-mapped bytes keep their contents. Mapping across the
    /// start of another mapping is a harness bug.
    pub fn map(&mut self, base: u32, length: u32) {
        let end = base as u64 + length as u64;
        assert!(end <= 1 << 32, "the mapping wraps the address space");
        if let Some(mapping) = self
            .mappings
            .iter_mut()
            .find(|mapping| mapping.base <= base && base as u64 <= mapping.end())
        {
            if end > mapping.end() {
                mapping
                    .bytes
                    .resize((end - mapping.base as u64) as usize, 0);
            }
        } else {
            self.mappings.push(Mapping {
                base,
                bytes: vec![0; length as usize],
            });
        }
        let mut spans: Vec<(u64, u64)> = self
            .mappings
            .iter()
            .map(|mapping| (mapping.base as u64, mapping.end()))
            .collect();
        spans.sort();
        for pair in spans.windows(2) {
            assert!(
                pair[0].1 <= pair[1].0,
                "mappings overlap at {:#x}",
                pair[1].0
            );
        }
    }

    /// Whether every byte of `address..address + length` is mapped.
    pub fn is_mapped(&self, address: u32, length: u32) -> bool {
        self.span(address, length).is_some()
    }

    /// The mapping and in-mapping offset holding `address..address + length` entirely.
    fn span(&self, address: u32, length: u32) -> Option<(usize, usize)> {
        let end = address as u64 + length as u64;
        self.mappings
            .iter()
            .position(|mapping| mapping.base <= address && end <= mapping.end())
            .map(|index| (index, (address - self.mappings[index].base) as usize))
    }

    /// The first unmapped byte of a range that is not wholly mapped.
    fn first_unmapped(&self, address: u32, length: u32) -> u32 {
        (0..length.max(1))
            .map(|offset| address.wrapping_add(offset))
            .find(|&byte| !self.is_mapped(byte, 1))
            .unwrap_or(address)
    }

    /// Read `out.len()` bytes at `address`.
    pub fn read(&self, address: u32, out: &mut [u8]) -> Result<(), Fault> {
        let Some((index, offset)) = self.span(address, out.len() as u32) else {
            return Err(Fault {
                address: self.first_unmapped(address, out.len() as u32),
            });
        };
        out.copy_from_slice(&self.mappings[index].bytes[offset..offset + out.len()]);
        Ok(())
    }

    /// Write `bytes` at `address`.
    pub fn write(&mut self, address: u32, bytes: &[u8]) -> Result<(), Fault> {
        let Some((index, offset)) = self.span(address, bytes.len() as u32) else {
            return Err(Fault {
                address: self.first_unmapped(address, bytes.len() as u32),
            });
        };
        self.mappings[index].bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// The mapped bytes of `address..address + length`, in place; none unless wholly mapped.
    pub fn slice_mut(&mut self, address: u32, length: u32) -> Option<&mut [u8]> {
        let (index, offset) = self.span(address, length)?;
        Some(&mut self.mappings[index].bytes[offset..offset + length as usize])
    }

    /// The bytes at `address..address + length` (a harness read: unmapped is a harness bug).
    pub fn bytes(&self, address: u32, length: u32) -> Vec<u8> {
        let mut out = vec![0; length as usize];
        self.read(address, &mut out)
            .unwrap_or_else(|fault| panic!("read of unmapped {:#x}", fault.address));
        out
    }

    /// The little-endian dword at `address`.
    pub fn u32_at(&self, address: u32) -> u32 {
        u32::from_le_bytes(self.bytes(address, 4).try_into().unwrap())
    }

    /// The NUL-terminated byte string at `address`, terminator excluded.
    pub fn c_string(&self, address: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            self.read(address + out.len() as u32, &mut byte)
                .unwrap_or_else(|fault| panic!("unterminated string at {:#x}", fault.address));
            if byte[0] == 0 {
                return out;
            }
            out.push(byte[0]);
        }
    }

    /// The NUL-terminated wide string at `address`, terminator excluded.
    pub fn wide_string(&self, address: u32) -> Vec<u16> {
        let mut out = Vec::new();
        let mut wide = [0u8; 2];
        loop {
            self.read(address + 2 * out.len() as u32, &mut wide)
                .unwrap_or_else(|fault| panic!("unterminated string at {:#x}", fault.address));
            match u16::from_le_bytes(wide) {
                0 => return out,
                unit => out.push(unit),
            }
        }
    }
}

/// The process parameters the kernel stages for the process before its first instruction: where
/// each string lives in the calling process's address space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProcessParameters {
    /// The command line (ANSI, NUL-terminated).
    pub command_line: u32,
    /// The environment block (wide, double-NUL-terminated).
    pub environment: u32,
    /// The image's path (ANSI, NUL-terminated).
    pub image_path: u32,
    /// The image path's staging room, terminator included: a path that fills it unterminated is
    /// malformed staging.
    pub image_path_room: u32,
}

/// An event's flavor (NtCreateEvent's EVENT_TYPE).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventType {
    /// Manual reset: signaled until cleared; one signal releases every waiter.
    Notification,
    /// Auto reset: one signal releases one waiter, and the release consumes it.
    Synchronization,
}

/// A file's position and size (FilePositionInformation and FileStandardInformation's end of file,
/// together: the two facts SetFilePointer needs).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FilePosition {
    /// Where the next read starts.
    pub position: u32,
    /// The file's size in bytes.
    pub size: u32,
}

/// A codepage's conversion tables, as the kernel maps them for the process.
#[derive(Clone, Copy)]
pub struct CodePageTable {
    /// The codepage's number.
    pub code_page: u32,
    /// The longest character in bytes (CPINFO.MaxCharSize).
    pub max_char_size: u32,
    /// The default character for unmapped code points.
    pub default_char: u8,
    /// Byte to UTF-16, for all 256 bytes.
    pub multi_byte_to_wide: &'static [u16; 256],
    /// UTF-16 to byte (the default character for code points the codepage lacks).
    pub wide_to_multi_byte: fn(u16) -> u8,
    /// The CT_CTYPE1 classification of a UTF-16 unit.
    pub ctype1: fn(u16) -> u16,
    /// Case mapping of a UTF-16 unit: to upper when the flag is set, else to lower.
    pub map_case: fn(u16, bool) -> u16,
}

/// The kernel-side operations of the kernel32 surface (see the module docs for the per-service
/// table).
pub trait KernelBoundary {
    /// The calling process's address space.
    fn memory(&mut self) -> &mut AddressSpace;

    /// NtTerminateProcess on the current process: every thread ends and the process reports
    /// `exit_status`. Never returns on the real system; host-side the call is recorded and returns,
    /// and nothing may be called after it.
    fn nt_terminate_process(&mut self, exit_status: u32);

    /// The PEB's process parameters: where the kernel staged the command line, the environment
    /// block, and the image path.
    fn process_parameters(&self) -> ProcessParameters;

    /// NtAllocateVirtualMemory on the current process: reserve and/or commit (`allocation_type`'s
    /// MEM_RESERVE / MEM_COMMIT) `size` bytes at `base` (NULL: the kernel picks). The base of the
    /// range on success.
    fn nt_allocate_virtual_memory(
        &mut self,
        base: u32,
        size: u32,
        allocation_type: u32,
    ) -> Result<u32, NtStatus>;

    /// NtClose: end the handle table's claim on the object `handle` names (the object itself lives
    /// on).
    fn nt_close(&mut self, handle: u32) -> Result<(), NtStatus>;

    /// NtCreateEvent: an unnamed event of `event_type`, signaled when `initial_state`; its handle.
    fn nt_create_event(
        &mut self,
        event_type: EventType,
        initial_state: bool,
    ) -> Result<u32, NtStatus>;

    /// NtSetEvent: signal the event `handle` names, releasing its waiters per its type.
    fn nt_set_event(&mut self, handle: u32) -> Result<(), NtStatus>;

    /// NtWaitForSingleObject, non-alertable: wait on the object `handle` names for `timeout` (100
    /// ns units, relative; none waits forever). The wait's status: STATUS_SUCCESS (signaled),
    /// STATUS_TIMEOUT, or a failure.
    fn nt_wait_for_single_object(&mut self, handle: u32, timeout: Option<i64>) -> NtStatus;

    /// NtDelayExecution, non-alertable: park the calling thread for `interval` (100 ns units,
    /// relative; zero yields; `i64::MIN` is the longest interval there is).
    fn nt_delay_execution(&mut self, interval: i64) -> NtStatus;

    /// NtCreateThread in the current process: a thread entering `start` with `parameter`,
    /// suspended once when `create_suspended`. Its handle and identifier.
    fn nt_create_thread(
        &mut self,
        start: u32,
        parameter: u32,
        create_suspended: bool,
    ) -> Result<(u32, u32), NtStatus>;

    /// NtSetInformationThread's ThreadBasePriority class: set the thread `handle` names to
    /// `increment` from its process's base (the saturation pins are +16 / -16).
    fn nt_set_information_thread(&mut self, handle: u32, increment: i32) -> Result<(), NtStatus>;

    /// NtSuspendThread: bump the suspend count of the thread `handle` names; the previous count.
    fn nt_suspend_thread(&mut self, handle: u32) -> Result<u32, NtStatus>;

    /// NtResumeThread: drop the suspend count of the thread `handle` names (not below zero); the
    /// previous count.
    fn nt_resume_thread(&mut self, handle: u32) -> Result<u32, NtStatus>;

    /// KeQueryTickCount: clock ticks since boot.
    fn ke_query_tick_count(&self) -> u64;

    /// KeQueryTimeIncrement: one clock tick, in 100 ns units.
    fn ke_query_time_increment(&self) -> u32;

    /// NtCreateFile for read access to an existing file (FILE_GENERIC_READ, FILE_OPEN, synchronous
    /// — the one request this surface serves): open `path` on the boot volume at its start. Its
    /// handle.
    fn nt_create_file(&mut self, path: &[u8]) -> Result<u32, NtStatus>;

    /// NtReadFile at the current position of the file `handle` names: up to `buffer.len()` bytes
    /// (what remains before the end), the position advanced past them. The count read.
    fn nt_read_file(&mut self, handle: u32, buffer: &mut [u8]) -> Result<u32, NtStatus>;

    /// NtQueryInformationFile: the position and size of the file `handle` names.
    fn nt_query_information_file(&mut self, handle: u32) -> Result<FilePosition, NtStatus>;

    /// NtSetInformationFile's FilePositionInformation class: move the file `handle` names to
    /// `position` (past the end is legal).
    fn nt_set_information_file(&mut self, handle: u32, position: u32) -> Result<(), NtStatus>;

    /// The console backend: `bytes` written to the console handle `handle` (the serial line on the
    /// target).
    fn write_console(&mut self, handle: u32, bytes: &[u8]);

    /// The process's ANSI codepage.
    fn ansi_code_page(&self) -> u32;

    /// The process's OEM codepage.
    fn oem_code_page(&self) -> u32;

    /// The conversion tables of `code_page`; none for a codepage the kernel maps no table for.
    fn code_page_table(&self, code_page: u32) -> Option<CodePageTable>;
}
