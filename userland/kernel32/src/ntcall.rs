//! A typed, safe layer over the ntdll imports the process calls make (CreateProcess and its
//! companions): one function per import, taking references, slices and `Option`s and answering a
//! `Result` with the failed service's status, so that the code over them holds no `unsafe`. The
//! structures the services fill are `#[repr(C)]` types of their own here
//! (SECTION_IMAGE_INFORMATION, PROCESS_BASIC_INFORMATION), and the process parameters block
//! RtlCreateProcessParameters makes is an owned value ([`ParametersBlock`]) freed when dropped.
//!
//! Memory the kernel reads or writes for kernel32's caller (ReadProcessMemory's buffer, another
//! process's addresses) is never touched here: a [`Source`] or [`Destination`] is an address and a
//! length the service probes, made safely from kernel32's own slices or, at an export, from the
//! caller's pointer under the export's contract.

use core::marker::PhantomData;
use core::mem::size_of;

use rtl::status::nt_success;

use crate::nt::{self, ClientId, ObjectAttributes, ProcessParameters, UnicodeString};
use crate::thread::{InitialTeb, CONTEXT_WORDS};

/// An NTSTATUS, as kernel32 handles them.
pub type NtStatus = u32;

/// A status as a `Result`: a success or informational status is `Ok`.
fn checked(status: NtStatus) -> Result<(), NtStatus> {
    if nt_success(status) {
        Ok(())
    } else {
        Err(status)
    }
}

/// The structures the services fill or take as bytes: integers only, without padding, so any
/// bytes of their size make one and their bytes are all initialized.
///
/// # Safety
///
/// Every bit pattern of the type's size is a valid value, and the type has no padding.
pub unsafe trait Plain: Copy {
    /// The value's bytes.
    fn bytes(&self) -> &[u8] {
        // SAFETY: the trait's contract: no padding, so every byte is initialized.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast(), size_of::<Self>()) }
    }

    /// The value's bytes, writable.
    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: the trait's contract: any bytes make a value.
        unsafe { core::slice::from_raw_parts_mut((self as *mut Self).cast(), size_of::<Self>()) }
    }
}

// SAFETY: an integer.
unsafe impl Plain for u32 {}
// SAFETY: integers.
unsafe impl Plain for [u8; 2] {}

/// SECTION_IMAGE_INFORMATION, NT 5.0's (0x30 bytes): an image section's entry point, stack sizes,
/// subsystem and characteristics (NtQuerySection's SectionImageInformation). Its addresses are
/// another process's, 32-bit on any host.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SectionImageInformation {
    pub transfer_address: u32,
    pub zero_bits: u32,
    pub maximum_stack_size: u32,
    pub committed_stack_size: u32,
    pub subsystem_type: u32,
    pub subsystem_version: u32,
    pub gp_value: u32,
    pub image_characteristics: u16,
    pub dll_characteristics: u16,
    pub machine: u16,
    pub image_contains_code: u8,
    pub spare: u8,
    pub loader_flags: u32,
    pub reserved: [u32; 2],
}

const _: () = assert!(size_of::<SectionImageInformation>() == 0x30);

// SAFETY: integers, laid out without padding (the assertion above).
unsafe impl Plain for SectionImageInformation {}

/// PROCESS_BASIC_INFORMATION (24 bytes): a process's exit status (STILL_ACTIVE while it runs), its
/// PEB's address, its affinity, its base priority, its id and its parent's.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessBasicInformation {
    pub exit_status: u32,
    pub peb_base_address: u32,
    pub affinity_mask: u32,
    pub base_priority: i32,
    pub unique_process_id: u32,
    pub inherited_from_unique_process_id: u32,
}

const _: () = assert!(size_of::<ProcessBasicInformation>() == 24);

// SAFETY: integers, without padding.
unsafe impl Plain for ProcessBasicInformation {}

// SAFETY: RTL_USER_PROCESS_PARAMETERS with 32-bit pointers: dwords and pairs of words, without
// padding (rtl::params asserts its size, 0x290).
unsafe impl Plain for rtl::params::ProcessParameters<u32> {}

/// Bytes a service reads: an address and a length (kernel32 never reads them itself).
#[derive(Clone, Copy)]
pub struct Source<'a> {
    address: usize,
    length: usize,
    _bytes: PhantomData<&'a [u8]>,
}

impl<'a> Source<'a> {
    /// Kernel32's own bytes.
    pub fn of(bytes: &'a [u8]) -> Source<'a> {
        Source {
            address: bytes.as_ptr() as usize,
            length: bytes.len(),
            _bytes: PhantomData,
        }
    }

    /// Kernel32's own UTF-16 units, as bytes.
    pub fn of_units(units: &'a [u16]) -> Source<'a> {
        Source {
            address: units.as_ptr() as usize,
            length: 2 * units.len(),
            _bytes: PhantomData,
        }
    }

    /// The caller's bytes at `address`, as the export received them (the service probes them).
    ///
    /// # Safety
    ///
    /// The export's caller gave the address and length; nothing of kernel32's lives there.
    pub unsafe fn caller(address: usize, length: usize) -> Source<'static> {
        Source {
            address,
            length,
            _bytes: PhantomData,
        }
    }
}

/// Bytes a service writes: an address and a length (kernel32 never touches them itself).
pub struct Destination<'a> {
    address: usize,
    length: usize,
    _bytes: PhantomData<&'a mut [u8]>,
}

impl<'a> Destination<'a> {
    /// Kernel32's own bytes.
    pub fn of(bytes: &'a mut [u8]) -> Destination<'a> {
        Destination {
            address: bytes.as_mut_ptr() as usize,
            length: bytes.len(),
            _bytes: PhantomData,
        }
    }

    /// The caller's bytes at `address`, as the export received them (the service probes them).
    ///
    /// # Safety
    ///
    /// The export's caller gave the address and length; nothing of kernel32's lives there.
    pub unsafe fn caller(address: usize, length: usize) -> Destination<'static> {
        Destination {
            address,
            length,
            _bytes: PhantomData,
        }
    }
}

/// The OBJECT_ATTRIBUTES of an unnamed object: inheritable when asked, its security descriptor
/// the caller's (as BaseFormatObjectAttributes makes them from a SECURITY_ATTRIBUTES).
pub fn unnamed_attributes(inherit: bool, security_descriptor: *const u8) -> ObjectAttributes {
    ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: core::ptr::null(),
        attributes: if inherit { crate::base::OBJ_INHERIT } else { 0 },
        security_descriptor,
        security_quality_of_service: core::ptr::null(),
    }
}

/// An optional reference as the services take it: a pointer, null for none.
fn pointer<T>(value: Option<&T>) -> *const T {
    value.map_or(core::ptr::null(), |value| value as *const T)
}

/// A UNICODE_STRING over `units` (its length in bytes; past a UNICODE_STRING's 0xFFFE bytes, none).
fn counted(units: &[u16]) -> Option<UnicodeString> {
    let bytes = u16::try_from(2 * units.len())
        .ok()
        .filter(|&bytes| bytes < 0xFFFF)?;
    Some(UnicodeString {
        length: bytes,
        maximum_length: bytes,
        buffer: units.as_ptr() as *mut u16,
    })
}

/// NtClose: a handle kernel32 made released.
pub fn close(handle: u32) {
    // SAFETY: ntdll's export.
    unsafe { nt::NtClose(handle) };
}

/// SECTION_ALL_ACCESS, the image section's protection (PAGE_EXECUTE) and SEC_IMAGE.
const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
const PAGE_EXECUTE: u32 = 0x10;
const SEC_IMAGE: u32 = 0x0100_0000;

/// NtCreateSection of an image (SEC_IMAGE, PAGE_EXECUTE) over an open file: the section's handle.
pub fn create_image_section(file: u32) -> Result<u32, NtStatus> {
    let mut section = 0;
    // SAFETY: ntdll's export, over the local above; no attributes, no maximum size.
    checked(unsafe {
        nt::NtCreateSection(
            &mut section,
            SECTION_ALL_ACCESS,
            core::ptr::null(),
            core::ptr::null(),
            PAGE_EXECUTE,
            SEC_IMAGE,
            file,
        )
    })?;
    Ok(section)
}

/// SectionImageInformation, NtQuerySection's class 1.
const SECTION_IMAGE_INFORMATION: u32 = 1;

/// NtQuerySection: an image section's SECTION_IMAGE_INFORMATION.
pub fn query_image(section: u32) -> Result<SectionImageInformation, NtStatus> {
    let mut information = SectionImageInformation::default();
    let bytes = information.bytes_mut();
    // SAFETY: ntdll's export, into the structure's bytes.
    checked(unsafe {
        nt::NtQuerySection(
            section,
            SECTION_IMAGE_INFORMATION,
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            core::ptr::null_mut(),
        )
    })?;
    Ok(information)
}

/// PROCESS_ALL_ACCESS: what CreateProcess's process handle grants.
const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;

/// NtCreateProcess: a process of the image section, its parent `parent`, the parent's inheritable
/// handles copied when `inherit_handles`; no debug or exception port. The process's handle.
pub fn create_process(
    attributes: Option<&ObjectAttributes>,
    parent: u32,
    inherit_handles: bool,
    section: u32,
) -> Result<u32, NtStatus> {
    let mut process = 0;
    // SAFETY: ntdll's export, over the local and the attributes.
    checked(unsafe {
        nt::NtCreateProcess(
            &mut process,
            PROCESS_ALL_ACCESS,
            pointer(attributes),
            parent,
            u32::from(inherit_handles),
            section,
            0,
            0,
        )
    })?;
    Ok(process)
}

/// NtOpenProcess: a handle with `access` to the process the client id names.
pub fn open_process(
    access: u32,
    attributes: &ObjectAttributes,
    client_id: &ClientId,
) -> Result<u32, NtStatus> {
    let mut process = 0;
    // SAFETY: ntdll's export, over the local and the structures.
    checked(unsafe { nt::NtOpenProcess(&mut process, access, attributes, client_id) })?;
    Ok(process)
}

/// NtQueryInformationProcess: the class's value into `out`, as long as it is.
pub fn query_information_process(process: u32, class: u32, out: &mut [u8]) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, into the buffer of its length.
    checked(unsafe {
        nt::NtQueryInformationProcess(
            process,
            class,
            out.as_mut_ptr(),
            out.len() as u32,
            core::ptr::null_mut(),
        )
    })
}

/// ProcessBasicInformation, NtQueryInformationProcess's class 0.
const PROCESS_BASIC_INFORMATION: u32 = 0;

/// A process's basic information (NtQueryInformationProcess, ProcessBasicInformation).
pub fn basic_information(process: u32) -> Result<ProcessBasicInformation, NtStatus> {
    let mut information = ProcessBasicInformation::default();
    query_information_process(process, PROCESS_BASIC_INFORMATION, information.bytes_mut())?;
    Ok(information)
}

/// NtSetInformationProcess: the class's value from `value`.
pub fn set_information_process(process: u32, class: u32, value: &[u8]) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, from the buffer of its length.
    checked(unsafe {
        nt::NtSetInformationProcess(process, class, value.as_ptr(), value.len() as u32)
    })
}

/// ObjectHandleFlagInformation, NtQueryObject's and NtSetInformationObject's class 4.
const OBJECT_HANDLE_FLAG_INFORMATION: u32 = 4;

/// OBJECT_HANDLE_FLAG_INFORMATION: a handle's inheritance and its protection from close, as
/// BOOLEANs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HandleFlags {
    pub inherit: u8,
    pub protect_from_close: u8,
}

const _: () = assert!(size_of::<HandleFlags>() == 2);

// SAFETY: integers, without padding.
unsafe impl Plain for HandleFlags {}

/// A handle's flags (NtQueryObject, ObjectHandleFlagInformation).
pub fn handle_flags(handle: u32) -> Result<HandleFlags, NtStatus> {
    let mut flags = HandleFlags::default();
    let out = flags.bytes_mut();
    // SAFETY: ntdll's export, into the structure's own bytes; no return length asked.
    checked(unsafe {
        nt::NtQueryObject(
            handle,
            OBJECT_HANDLE_FLAG_INFORMATION,
            out.as_mut_ptr(),
            out.len() as u32,
            core::ptr::null_mut(),
        )
    })?;
    Ok(flags)
}

/// Set a handle's flags (NtSetInformationObject, ObjectHandleFlagInformation).
pub fn set_handle_flags(handle: u32, flags: HandleFlags) -> Result<(), NtStatus> {
    let bytes = flags.bytes();
    // SAFETY: ntdll's export, from the structure's own bytes.
    checked(unsafe {
        nt::NtSetInformationObject(
            handle,
            OBJECT_HANDLE_FLAG_INFORMATION,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    })
}

/// NtTerminateProcess of a process kernel32 holds a handle to (never a null handle: that names the
/// caller's other threads).
pub fn terminate_process(process: u32, status: NtStatus) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export.
    checked(unsafe { nt::NtTerminateProcess(process, status) })
}

/// NtAllocateVirtualMemory in a process: `size` bytes at `base` (anywhere for zero) of the type and
/// protection; the base and size settled on.
pub fn allocate_virtual_memory(
    process: u32,
    base: usize,
    size: usize,
    kind: u32,
    protect: u32,
) -> Result<(usize, usize), NtStatus> {
    let (mut base, mut size) = (base, size);
    // SAFETY: ntdll's export, over the locals above.
    checked(unsafe {
        nt::NtAllocateVirtualMemory(process, &mut base, 0, &mut size, kind, protect)
    })?;
    Ok((base, size))
}

/// MEM_RELEASE: a whole reservation given back.
const MEM_RELEASE: u32 = 0x8000;

/// NtFreeVirtualMemory in a process: the reservation at `base` released whole (a release that
/// fails leaves it, as nothing more can be done for it).
pub fn free_virtual_memory(process: u32, base: usize) {
    let (mut base, mut size) = (base, 0usize);
    // SAFETY: ntdll's export, over the locals above.
    unsafe { nt::NtFreeVirtualMemory(process, &mut base, &mut size, MEM_RELEASE) };
}

/// NtFreeVirtualMemory in a process, of either kind (MEM_RELEASE, MEM_DECOMMIT): the pages of
/// `[base, base + size)`, or a whole reservation for a release of size zero.
pub fn free_virtual_memory_range(
    process: u32,
    base: usize,
    size: usize,
    kind: u32,
) -> Result<(), NtStatus> {
    let (mut base, mut size) = (base, size);
    // SAFETY: ntdll's export, over the locals above.
    checked(unsafe { nt::NtFreeVirtualMemory(process, &mut base, &mut size, kind) })
}

/// NtProtectVirtualMemory in a process, the old protection written where the caller asked: the
/// service probes `old` before anything changes (a missing one is its access violation).
pub fn protect_virtual_memory_reporting(
    process: u32,
    base: usize,
    size: usize,
    protect: u32,
    old: Option<&mut u32>,
) -> Result<(), NtStatus> {
    let (mut base, mut size) = (base, size);
    // SAFETY: ntdll's export, over the locals above and the caller's old protection (or null).
    checked(unsafe {
        nt::NtProtectVirtualMemory(
            process,
            &mut base,
            &mut size,
            protect,
            old.map_or(core::ptr::null_mut(), |old| old as *mut u32),
        )
    })
}

/// MemoryBasicInformation, NtQueryVirtualMemory's class 0.
const MEMORY_BASIC_INFORMATION: u32 = 0;

/// NtQueryVirtualMemory: the MEMORY_BASIC_INFORMATION of a process's pages from `address` into
/// the destination (the service probes it); the structure's size.
pub fn query_virtual_memory(
    process: u32,
    address: usize,
    destination: Destination,
) -> Result<usize, NtStatus> {
    let mut returned = 0;
    // SAFETY: ntdll's export: the service probes the destination (kernel32's own bytes, or its
    // caller's under the export's contract).
    checked(unsafe {
        nt::NtQueryVirtualMemory(
            process,
            address,
            MEMORY_BASIC_INFORMATION,
            destination.address as *mut u8,
            destination.length,
            &mut returned,
        )
    })?;
    Ok(returned)
}

/// NtProtectVirtualMemory in a process: the pages of `[base, base + size)` given the protection;
/// the protection they had.
pub fn protect_virtual_memory(
    process: u32,
    base: usize,
    size: usize,
    protect: u32,
) -> Result<u32, NtStatus> {
    let (mut base, mut size, mut old) = (base, size, 0);
    // SAFETY: ntdll's export, over the locals above.
    checked(unsafe {
        nt::NtProtectVirtualMemory(process, &mut base, &mut size, protect, &mut old)
    })?;
    Ok(old)
}

/// NtReadVirtualMemory: a process's bytes at `address` into the destination, the count written
/// where asked (the service writes it, or leaves it, as it does).
pub fn read_virtual_memory(
    process: u32,
    address: usize,
    destination: Destination,
    count: Option<&mut u32>,
) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export: the service probes the destination (kernel32's own bytes, or its
    // caller's under the export's contract) and the count.
    checked(unsafe {
        nt::NtReadVirtualMemory(
            process,
            address,
            destination.address as *mut u8,
            destination.length as u32,
            count.map_or(core::ptr::null_mut(), |count| count as *mut u32),
        )
    })
}

/// NtWriteVirtualMemory: the source's bytes into a process at `address`, the count written where
/// asked.
pub fn write_virtual_memory(
    process: u32,
    address: usize,
    source: Source,
    count: Option<&mut u32>,
) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export: the service probes the source (kernel32's own bytes, or its caller's
    // under the export's contract) and the count.
    checked(unsafe {
        nt::NtWriteVirtualMemory(
            process,
            address,
            source.address as *const u8,
            source.length as u32,
            count.map_or(core::ptr::null_mut(), |count| count as *mut u32),
        )
    })
}

/// NtFlushInstructionCache: a process's instruction cache over `[address, address + length)` made
/// to see the writes to its memory.
pub fn flush_instruction_cache(
    process: u32,
    address: usize,
    length: usize,
) -> Result<(), NtStatus> {
    // SAFETY: ntdll's export, over plain values: the service reads no memory.
    checked(unsafe { nt::NtFlushInstructionCache(process, address, length as u32) })
}

/// NtCreateThread: a thread of `process` on the stack the INITIAL_TEB describes, starting in the
/// CONTEXT, suspended when asked; its handle and client id.
pub fn create_thread(
    process: u32,
    access: u32,
    attributes: Option<&ObjectAttributes>,
    context: &[u32; CONTEXT_WORDS],
    stack: &InitialTeb,
    suspended: bool,
) -> Result<(u32, ClientId), NtStatus> {
    let (mut thread, mut client_id) = (0u32, [0usize; 2]);
    // SAFETY: ntdll's export, over the locals and the structures.
    checked(unsafe {
        nt::NtCreateThread(
            &mut thread,
            access,
            pointer(attributes),
            process,
            client_id.as_mut_ptr(),
            context.as_ptr(),
            stack,
            u32::from(suspended),
        )
    })?;
    Ok((
        thread,
        ClientId {
            unique_process: client_id[0],
            unique_thread: client_id[1],
        },
    ))
}

/// NtResumeThread: the thread's suspend count lowered; the count it had.
pub fn resume_thread(thread: u32) -> Result<u32, NtStatus> {
    let mut previous = 0;
    // SAFETY: ntdll's export, over the local above.
    checked(unsafe { nt::NtResumeThread(thread, &mut previous) })?;
    Ok(previous)
}

/// REG_SZ: the option's text.
const REG_SZ: u32 = 1;

/// LdrQueryImageFileExecutionOptions: the text option `option` (NUL-terminated) of the image at
/// `image_path` into `buffer`; the bytes it took.
pub fn image_file_execution_option(
    image_path: &[u16],
    option: &[u16],
    buffer: &mut [u8],
) -> Result<u32, NtStatus> {
    debug_assert_eq!(
        option.last(),
        Some(&0),
        "the option's name is NUL-terminated"
    );
    let image = counted(image_path).ok_or(rtl::status::STATUS_NAME_TOO_LONG)?;
    let mut returned = 0;
    // SAFETY: ntdll's export, over the strings and into the buffer of its length.
    checked(unsafe {
        nt::LdrQueryImageFileExecutionOptions(
            &image,
            option.as_ptr(),
            REG_SZ,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut returned,
        )
    })?;
    Ok(returned)
}

/// What a new process parameters block holds: the image's path, the DLL search path, the current
/// directory (none: the caller's own), the command line, the environment's address (in the
/// process the block is for), the window title, desktop and shell information, and the C
/// runtime's data (none: no buffer).
pub struct ParameterStrings<'a> {
    pub image_path_name: &'a [u16],
    pub dll_path: &'a [u16],
    pub current_directory: Option<&'a [u16]>,
    pub command_line: &'a [u16],
    pub environment: usize,
    pub window_title: Option<&'a [u16]>,
    pub desktop_info: Option<&'a [u16]>,
    pub shell_info: Option<&'a [u16]>,
    pub runtime_data: Option<&'a [u8]>,
}

/// A process parameters block RtlCreateProcessParameters made, denormalized: freed
/// (RtlDestroyProcessParameters) when dropped.
pub struct ParametersBlock(*mut ProcessParameters);

impl ParametersBlock {
    /// The block's structure.
    pub fn header(&self) -> &ProcessParameters {
        // SAFETY: ntdll's block, the structure at its start, ours until it is destroyed.
        unsafe { &*self.0 }
    }

    /// The block's structure, writable.
    pub fn header_mut(&mut self) -> &mut ProcessParameters {
        // SAFETY: as above.
        unsafe { &mut *self.0 }
    }

    /// The strings' room after the structure, to the block's length.
    pub fn strings(&self) -> &[u8] {
        let header = size_of::<ProcessParameters>();
        let length = (self.header().length as usize).saturating_sub(header);
        // SAFETY: the block holds its Length bytes, the structure's first.
        unsafe { core::slice::from_raw_parts((self.0 as *const u8).add(header), length) }
    }
}

impl Drop for ParametersBlock {
    fn drop(&mut self) {
        // SAFETY: ntdll's export, over the block it made.
        unsafe { nt::RtlDestroyProcessParameters(self.0) };
    }
}

/// RtlCreateProcessParameters: a new block of the strings. A string past a UNICODE_STRING's room
/// is STATUS_NAME_TOO_LONG.
pub fn create_process_parameters(strings: &ParameterStrings) -> Result<ParametersBlock, NtStatus> {
    const TOO_LONG: NtStatus = rtl::status::STATUS_NAME_TOO_LONG;
    let required = |units: &[u16]| counted(units).ok_or(TOO_LONG);
    let optional = |units: Option<&[u16]>| units.map(required).transpose();
    let image_path_name = required(strings.image_path_name)?;
    let dll_path = required(strings.dll_path)?;
    let current_directory = optional(strings.current_directory)?;
    let command_line = required(strings.command_line)?;
    let window_title = optional(strings.window_title)?;
    let desktop_info = optional(strings.desktop_info)?;
    let shell_info = optional(strings.shell_info)?;
    let runtime_data = strings
        .runtime_data
        .map(|bytes| {
            let length = u16::try_from(bytes.len()).map_err(|_| TOO_LONG)?;
            Ok::<_, NtStatus>(UnicodeString {
                length,
                maximum_length: length,
                buffer: bytes.as_ptr() as *mut u16,
            })
        })
        .transpose()?;
    let mut block = core::ptr::null_mut();
    // SAFETY: ntdll's export, over the strings above (each over its slice, read only) and the
    // local slot.
    checked(unsafe {
        nt::RtlCreateProcessParameters(
            &mut block,
            &image_path_name,
            &dll_path,
            pointer(current_directory.as_ref()),
            &command_line,
            strings.environment,
            pointer(window_title.as_ref()),
            pointer(desktop_info.as_ref()),
            pointer(shell_info.as_ref()),
            pointer(runtime_data.as_ref()),
        )
    })?;
    Ok(ParametersBlock(block))
}

/// RtlMultiByteToUnicodeN: ANSI bytes into UTF-16 units (code page 1252: one unit a byte), as many
/// as `out` holds; the units written.
pub fn multi_byte_to_unicode(out: &mut [u16], bytes: &[u8]) -> usize {
    let mut written = 0u32;
    // SAFETY: ntdll's export, into the buffer and from the bytes, of the sizes given.
    unsafe {
        nt::RtlMultiByteToUnicodeN(
            out.as_mut_ptr(),
            (2 * out.len()) as u32,
            &mut written,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    written as usize / 2
}

/// RtlGetFullPathName_U: a path made full against the current directory, into `out`; its length
/// in units when it fits with its terminator, none otherwise (or for a path ntdll cannot make).
pub fn full_path_name(path: &[u16], out: &mut [u16]) -> Option<usize> {
    debug_assert_eq!(path.last(), Some(&0), "the path is NUL-terminated");
    let mut part = core::ptr::null_mut();
    // SAFETY: ntdll's export, over the terminated path and into the buffer of its size.
    let bytes = unsafe {
        nt::RtlGetFullPathName_U(
            path.as_ptr(),
            (2 * out.len()) as u32,
            out.as_mut_ptr(),
            &mut part,
        )
    } as usize;
    (bytes != 0 && bytes < 2 * out.len()).then_some(bytes / 2)
}

/// RtlAllocateHeap on the process heap: a block of `bytes` (8-byte aligned), none when the heap has
/// no room.
pub fn allocate_heap(bytes: usize) -> Option<core::ptr::NonNull<u8>> {
    // SAFETY: ntdll's export, on the process heap.
    core::ptr::NonNull::new(unsafe { nt::RtlAllocateHeap(crate::base::process_heap(), 0, bytes) })
}

/// RtlFreeHeap on the process heap: a block [`allocate_heap`] made given back.
///
/// # Safety
///
/// `block` is a block [`allocate_heap`] made, not used again.
pub unsafe fn free_heap(block: core::ptr::NonNull<u8>) {
    // SAFETY: ntdll's export, over the caller's block of the process heap.
    unsafe { nt::RtlFreeHeap(crate::base::process_heap(), 0, block.as_ptr()) };
}

/// RtlRaiseStatus: the status raised as an exception in the caller (it does not return), as
/// Windows 2000's kernel32 faults where it reads through a missing pointer.
pub fn raise_status(status: NtStatus) -> ! {
    // SAFETY: ntdll's export: it does not return.
    unsafe { nt::RtlRaiseStatus(status) }
}
