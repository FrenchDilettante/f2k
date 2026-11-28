//! The host tests' child process: the one NtCreateProcess makes, its address space a list of
//! regions as the kernel lays a new process out (its image and its PEB; an allocation anywhere
//! takes the lowest free range on a 64 KiB boundary, as Windows 2000's does), and the process,
//! section and memory services over it. A service named by [`fail`] fails once with the status.

use std::cell::RefCell;
use std::string::String;
use std::vec::Vec;

use super::{ClientId, ObjectAttributes, ProcessParameters, UnicodeString};

/// The handle NtCreateProcess hands out, and the one NtOpenProcess hands out for the child.
pub const CHILD_PROCESS: u32 = 0x80;
pub const OPENED_PROCESS: u32 = 0x84;
/// The child's process id.
pub const CHILD_ID: usize = 0x2C;
/// Where the child's PEB and image are, and the image's size.
pub const CHILD_PEB: usize = 0x7FFD_F000;
pub const CHILD_IMAGE_BASE: usize = 0x0040_0000;
pub const CHILD_IMAGE_SIZE: usize = 0x6000;
/// The image's entry point, as the section describes it, and its stack sizes (the MSVC
/// linker's defaults).
pub const CHILD_ENTRY: u32 = 0x0040_1234;
pub const STACK_RESERVE: u32 = 0x10_0000;
pub const STACK_COMMIT: u32 = 0x1000;

const PAGE: usize = 0x1000;
const GRANULARITY: usize = 0x1_0000;
/// The lowest address an allocation takes, and the end of the user address space.
const LOWEST: usize = 0x1_0000;
const HIGHEST: usize = 0x7FFE_0000;

const MEM_RESERVE: u32 = 0x2000;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
/// The protections a write may go through.
const WRITABLE: u32 = 0x04 | 0x08 | 0x40 | 0x80;

use rtl::status::{
    STATUS_ACCESS_VIOLATION,
    STATUS_CONFLICTING_ADDRESSES,
    STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_CID,
    STATUS_INVALID_HANDLE,
    STATUS_INVALID_INFO_CLASS,
    STATUS_NO_MEMORY,
    STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_PARTIAL_COPY,
    STATUS_PROCESS_IS_TERMINATING,
};

/// A range of the child's address space: its base, its protection (the whole range's) and
/// its bytes.
#[derive(Clone, Debug)]
pub struct Region {
    pub base: usize,
    pub protect: u32,
    pub bytes: Vec<u8>,
}

/// The child as the stand-ins keep it.
#[derive(Clone, Debug)]
pub struct Child {
    /// NtCreateProcess's access, parent, InheritObjectTable, whether its handle is
    /// inheritable (OBJ_INHERIT), and section.
    pub access: u32,
    pub parent: u32,
    pub inherit_handles: bool,
    pub inheritable: bool,
    pub section: u32,
    pub regions: Vec<Region>,
    /// The memory services' calls on it: the service, the base and size settled on, the
    /// allocation type or the protection.
    pub vm: Vec<(&'static str, usize, usize, u32)>,
    /// Its exit status (STILL_ACTIVE while it runs), and what NtSetInformationProcess set.
    pub exit_status: u32,
    pub information: Vec<(u32, Vec<u8>)>,
}

impl Child {
    /// The region holding all of `[at, at + length)`.
    fn region_of(&mut self, at: usize, length: usize) -> Option<&mut Region> {
        self.regions
            .iter_mut()
            .find(|region| at >= region.base && at + length <= region.base + region.bytes.len())
    }

    /// Whether `[at, at + length)` meets no region.
    fn free(&self, at: usize, length: usize) -> bool {
        self.regions
            .iter()
            .all(|region| at + length <= region.base || at >= region.base + region.bytes.len())
    }
}

/// What RtlCreateProcessParameters was handed: its strings (none for a null one) and the
/// environment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MadeParameters {
    pub image_path_name: String,
    pub dll_path: Option<String>,
    pub current_directory: Option<String>,
    pub command_line: Option<String>,
    pub environment: usize,
    pub window_title: Option<String>,
    pub desktop_info: Option<String>,
    pub shell_info: Option<String>,
    pub runtime_data: Option<Vec<u8>>,
}

std::thread_local! {
    pub static CHILD: RefCell<Option<Child>> = const { RefCell::new(None) };
    /// NtQuerySection's SECTION_IMAGE_INFORMATION, as dwords.
    pub static SECTION_IMAGE: RefCell<[u32; 12]> = const { RefCell::new(image(0x0103, 3)) };
    /// The services to fail, once each, and their statuses.
    pub static FAILING: RefCell<Vec<(&'static str, u32)>> = const { RefCell::new(Vec::new()) };
    /// The options LdrQueryImageFileExecutionOptions was asked: the image and the option.
    pub static OPTIONS_ASKED: RefCell<Vec<(String, String)>> = const { RefCell::new(Vec::new()) };
    /// The blocks RtlCreateProcessParameters made and RtlDestroyProcessParameters freed.
    pub static PARAMETERS_MADE: RefCell<Vec<MadeParameters>> = const { RefCell::new(Vec::new()) };
    pub static PARAMETERS_DESTROYED: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    /// NtOpenProcess's calls: the access, the attributes' flags and the process id.
    pub static OPENED: RefCell<Vec<(u32, u32, usize)>> = const { RefCell::new(Vec::new()) };
}

/// A program's SECTION_IMAGE_INFORMATION: the entry point, the stack sizes, the subsystem
/// (version 4.0), the image's characteristics, an i386 image with code.
pub const fn image(characteristics: u16, subsystem: u32) -> [u32; 12] {
    [
        CHILD_ENTRY,
        0,
        STACK_RESERVE,
        STACK_COMMIT,
        subsystem,
        0x0004_0000,
        0,
        characteristics as u32,
        0x014C | 1 << 16,
        0,
        0,
        0,
    ]
}

/// No child, nothing recorded, no failure arranged, a console program's section.
pub fn reset() {
    CHILD.with(|child| *child.borrow_mut() = None);
    SECTION_IMAGE.with(|words| *words.borrow_mut() = image(0x0103, 3));
    FAILING.with(|failing| failing.borrow_mut().clear());
    OPTIONS_ASKED.with(|asked| asked.borrow_mut().clear());
    PARAMETERS_MADE.with(|made| made.borrow_mut().clear());
    PARAMETERS_DESTROYED.with(|destroyed| destroyed.borrow_mut().clear());
    OPENED.with(|opened| opened.borrow_mut().clear());
}

/// Fail `service` once with `status`.
pub fn fail(service: &'static str, status: u32) {
    FAILING.with(|failing| failing.borrow_mut().push((service, status)));
}

/// The failure arranged for `service`, taken.
pub fn failing(service: &str) -> Option<u32> {
    FAILING.with(|failing| {
        let mut failing = failing.borrow_mut();
        let at = failing.iter().position(|&(name, _)| name == service)?;
        Some(failing.remove(at).1)
    })
}

/// Whether `handle` names the child.
pub fn is_child(handle: u32) -> bool {
    (handle == CHILD_PROCESS || handle == OPENED_PROCESS)
        && CHILD.with(|child| child.borrow().is_some())
}

/// `body` over the child (there is one).
pub fn with_child<R>(body: impl FnOnce(&mut Child) -> R) -> R {
    CHILD.with(|child| body(child.borrow_mut().as_mut().expect("a child process")))
}

/// The child's bytes at `at`.
pub fn child_bytes(at: usize, length: usize) -> Vec<u8> {
    with_child(|child| {
        let region = child.region_of(at, length).expect("mapped in the child");
        region.bytes[at - region.base..][..length].to_vec()
    })
}

/// The child's dword at `at`.
pub fn child_dword(at: usize) -> u32 {
    u32::from_le_bytes(child_bytes(at, 4).try_into().unwrap())
}

/// The child's memory calls since the last look.
pub fn child_vm() -> Vec<(&'static str, usize, usize, u32)> {
    with_child(|child| std::mem::take(&mut child.vm))
}

/// NtAllocateVirtualMemory in the child: anywhere (the lowest free range on a 64 KiB boundary)
/// for a null base; at a base, a commit inside a reservation, or a reservation of a free
/// range on a boundary (STATUS_CONFLICTING_ADDRESSES otherwise).
pub fn allocate(base: &mut usize, size: &mut usize, kind: u32, protect: u32) -> u32 {
    if let Some(status) = failing("NtAllocateVirtualMemory") {
        return status;
    }
    with_child(|child| {
        let (start, end) = (*base & !(PAGE - 1), (*base + *size).next_multiple_of(PAGE));
        let length = end - start;
        let at = if start == 0 {
            let Some(at) = (LOWEST..HIGHEST - length)
                .step_by(GRANULARITY)
                .find(|&at| child.free(at, length))
            else {
                return STATUS_NO_MEMORY;
            };
            at
        } else if child.region_of(start, length).is_some() {
            child.vm.push(("allocate", start, length, kind));
            (*base, *size) = (start, length);
            return 0;
        } else if kind & MEM_RESERVE != 0 && start % GRANULARITY == 0 && child.free(start, length) {
            start
        } else {
            return STATUS_CONFLICTING_ADDRESSES;
        };
        child.regions.push(Region {
            base: at,
            protect,
            bytes: std::vec![0; length],
        });
        child.vm.push(("allocate", at, length, kind));
        (*base, *size) = (at, length);
        0
    })
}

/// NtProtectVirtualMemory in the child: the region's protection replaced, the old one
/// answered; STATUS_CONFLICTING_ADDRESSES for a range no region holds.
pub fn protect(base: &mut usize, size: &mut usize, protect: u32, old: &mut u32) -> u32 {
    if let Some(status) = failing("NtProtectVirtualMemory") {
        return status;
    }
    with_child(|child| {
        let (start, end) = (*base & !(PAGE - 1), (*base + *size).next_multiple_of(PAGE));
        let Some(region) = child.region_of(start, (end - start).max(1)) else {
            return STATUS_CONFLICTING_ADDRESSES;
        };
        *old = core::mem::replace(&mut region.protect, protect);
        child.vm.push(("protect", start, end - start, protect));
        (*base, *size) = (start, end - start);
        0
    })
}

/// NtFreeVirtualMemory in the child: the region at `base` released.
pub fn free(base: usize, kind: u32) -> u32 {
    with_child(|child| {
        child.vm.push(("free", base, 0, kind));
        child.regions.retain(|region| region.base != base);
        0
    })
}

/// NtQueryInformationProcess on the child: its basic information.
///
/// # Safety
///
/// `information` holds `length` bytes.
pub unsafe fn query(class: u32, information: *mut u8, length: u32) -> u32 {
    if class != 0 {
        return STATUS_INVALID_INFO_CLASS;
    }
    if length != 24 {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    let exit_status = with_child(|child| child.exit_status);
    let words = [
        exit_status,
        CHILD_PEB as u32,
        1,
        8,
        CHILD_ID as u32,
        super::threads::PROCESS_ID as u32,
    ];
    for (at, word) in words.iter().enumerate() {
        // SAFETY: the caller's structure, 24 bytes.
        unsafe { (information as *mut u32).add(at).write_unaligned(*word) };
    }
    0
}

/// NtSetInformationProcess on the child: the class and its value recorded.
pub fn set(class: u32, value: &[u8]) -> u32 {
    with_child(|child| child.information.push((class, value.to_vec())));
    0
}

/// NtTerminateProcess of the child: its exit status set; an ended child is
/// STATUS_PROCESS_IS_TERMINATING.
pub fn terminate(status: u32) -> u32 {
    with_child(|child| {
        if child.exit_status != 259 {
            return STATUS_PROCESS_IS_TERMINATING;
        }
        child.exit_status = status;
        0
    })
}

/// A UNICODE_STRING's text; none for a null one.
///
/// # Safety
///
/// `string` is null or a UNICODE_STRING whose buffer holds its length.
unsafe fn text(string: *const UnicodeString) -> Option<String> {
    // SAFETY: the caller's contract.
    let bytes = unsafe { bytes(string) }?;
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// A UNICODE_STRING's bytes; none for a null one.
///
/// # Safety
///
/// As [`text`].
unsafe fn bytes<'a>(string: *const UnicodeString) -> Option<&'a [u8]> {
    // SAFETY: the caller's contract.
    let string = unsafe { string.as_ref() }?;
    if string.length == 0 {
        return Some(&[]);
    }
    // SAFETY: as above.
    Some(unsafe { core::slice::from_raw_parts(string.buffer as *const u8, string.length as usize) })
}

/// NtCreateProcess: the child made (its image and PEB mapped, running), its handle written.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn NtCreateProcess(
    handle: *mut u32,
    access: u32,
    attributes: *const ObjectAttributes,
    parent: u32,
    inherit_object_table: u32,
    section: u32,
    _debug_port: u32,
    _exception_port: u32,
) -> u32 {
    if let Some(status) = failing("NtCreateProcess") {
        return status;
    }
    let mut image = std::vec![0u8; CHILD_IMAGE_SIZE];
    image[..2].copy_from_slice(b"MZ");
    let child = Child {
        access,
        parent,
        inherit_handles: inherit_object_table != 0,
        // SAFETY: the caller's attributes, when given.
        inheritable: unsafe { attributes.as_ref() }
            .is_some_and(|attributes| attributes.attributes & 2 != 0),
        section,
        regions: std::vec![
            Region {
                base: CHILD_IMAGE_BASE,
                protect: PAGE_READONLY,
                bytes: image,
            },
            Region {
                base: CHILD_PEB,
                protect: PAGE_READWRITE,
                bytes: std::vec![0; PAGE],
            },
        ],
        vm: Vec::new(),
        exit_status: 259,
        information: Vec::new(),
    };
    CHILD.with(|cell| *cell.borrow_mut() = Some(child));
    // SAFETY: the caller's handle slot.
    unsafe { handle.write(CHILD_PROCESS) };
    0
}

/// NtQuerySection: SectionImageInformation, [`SECTION_IMAGE`]'s.
pub unsafe extern "system" fn NtQuerySection(
    _section: u32,
    class: u32,
    information: *mut u8,
    length: u32,
    returned: *mut u32,
) -> u32 {
    if let Some(status) = failing("NtQuerySection") {
        return status;
    }
    if class != 1 {
        return STATUS_INVALID_INFO_CLASS;
    }
    if length < 0x30 {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    let words = SECTION_IMAGE.with(|words| *words.borrow());
    // SAFETY: the caller's structure, 0x30 bytes, and its count when given.
    unsafe {
        for (at, word) in words.iter().enumerate() {
            (information as *mut u32).add(at).write_unaligned(*word);
        }
        if !returned.is_null() {
            returned.write(0x30);
        }
    }
    0
}

/// NtOpenThread: thread id 12, the stand-in process's thread's, opens it (the handle
/// [`OPENED_THREAD`]); any other is STATUS_INVALID_CID.
pub unsafe extern "system" fn NtOpenThread(
    handle: *mut u32,
    _access: u32,
    _attributes: *const ObjectAttributes,
    client_id: *const ClientId,
) -> u32 {
    // SAFETY: the caller's structure.
    let id = unsafe { (*client_id).unique_thread };
    if id != 12 {
        return STATUS_INVALID_CID;
    }
    // SAFETY: the caller's handle slot.
    unsafe { handle.write(OPENED_THREAD) };
    0
}

/// The handle NtOpenThread hands out.
pub const OPENED_THREAD: u32 = 0x88;

/// NtOpenProcess: the call recorded; the child's id opens it, any other is
/// STATUS_INVALID_CID.
pub unsafe extern "system" fn NtOpenProcess(
    handle: *mut u32,
    access: u32,
    attributes: *const ObjectAttributes,
    client_id: *const ClientId,
) -> u32 {
    // SAFETY: the caller's structures.
    let (flags, id) = unsafe { ((*attributes).attributes, (*client_id).unique_process) };
    OPENED.with(|opened| opened.borrow_mut().push((access, flags, id)));
    if let Some(status) = failing("NtOpenProcess") {
        return status;
    }
    if id != CHILD_ID || CHILD.with(|child| child.borrow().is_none()) {
        return STATUS_INVALID_CID;
    }
    // SAFETY: the caller's handle slot.
    unsafe { handle.write(OPENED_PROCESS) };
    0
}

/// NtReadVirtualMemory: the child's bytes (STATUS_PARTIAL_COPY, none copied, past what it
/// maps), or the calling process's own; the count written where asked.
pub unsafe extern "system" fn NtReadVirtualMemory(
    process: u32,
    address: usize,
    buffer: *mut u8,
    length: u32,
    read: *mut u32,
) -> u32 {
    if let Some(status) = failing("NtReadVirtualMemory") {
        return status;
    }
    let length = length as usize;
    let (status, count) = if process == super::threads::CURRENT_PROCESS {
        // SAFETY: the test's own memory, `length` bytes each side.
        unsafe { buffer.copy_from_nonoverlapping(address as *const u8, length) };
        (0, length)
    } else if is_child(process) {
        let bytes = with_child(|child| {
            child
                .region_of(address, length)
                .map(|region| region.bytes[address - region.base..][..length].to_vec())
        });
        match bytes {
            Some(bytes) => {
                // SAFETY: the caller's buffer, `length` bytes.
                unsafe { buffer.copy_from_nonoverlapping(bytes.as_ptr(), length) };
                (0, length)
            }
            None => (STATUS_PARTIAL_COPY, 0),
        }
    } else {
        return STATUS_INVALID_HANDLE;
    };
    if !read.is_null() {
        // SAFETY: the caller's count.
        unsafe { read.write(count as u32) };
    }
    status
}

/// NtWriteVirtualMemory: into the child where it maps the bytes writable
/// (STATUS_ACCESS_VIOLATION where it maps them otherwise, STATUS_PARTIAL_COPY past what it
/// maps), or the calling process's own; the count written where asked.
pub unsafe extern "system" fn NtWriteVirtualMemory(
    process: u32,
    address: usize,
    buffer: *const u8,
    length: u32,
    written: *mut u32,
) -> u32 {
    if let Some(status) = failing("NtWriteVirtualMemory") {
        return status;
    }
    let length = length as usize;
    let source = if length == 0 {
        &[][..]
    } else {
        // SAFETY: the caller's buffer, `length` bytes.
        unsafe { core::slice::from_raw_parts(buffer, length) }
    };
    let (status, count) = if process == super::threads::CURRENT_PROCESS {
        // SAFETY: the test's own memory, `length` bytes.
        unsafe { (address as *mut u8).copy_from_nonoverlapping(buffer, length) };
        (0, length)
    } else if is_child(process) {
        with_child(|child| match child.region_of(address, length) {
            Some(region) if region.protect & WRITABLE != 0 => {
                region.bytes[address - region.base..][..length].copy_from_slice(source);
                (0, length)
            }
            Some(_) => (STATUS_ACCESS_VIOLATION, 0),
            None => (STATUS_PARTIAL_COPY, 0),
        })
    } else {
        return STATUS_INVALID_HANDLE;
    };
    if !written.is_null() {
        // SAFETY: the caller's count.
        unsafe { written.write(count as u32) };
    }
    status
}

/// NtFlushInstructionCache: recorded among the child's memory calls ("flush", the range); the
/// calling process's own is nothing to record.
pub unsafe extern "system" fn NtFlushInstructionCache(
    process: u32,
    address: usize,
    length: u32,
) -> u32 {
    if let Some(status) = failing("NtFlushInstructionCache") {
        return status;
    }
    if process == super::threads::CURRENT_PROCESS {
        return 0;
    }
    if !is_child(process) {
        return STATUS_INVALID_HANDLE;
    }
    with_child(|child| child.vm.push(("flush", address, length as usize, 0)));
    0
}

/// LdrQueryImageFileExecutionOptions: the question recorded; no image has options.
pub unsafe extern "system" fn LdrQueryImageFileExecutionOptions(
    image: *const UnicodeString,
    option: *const u16,
    _kind: u32,
    _buffer: *mut u8,
    _length: u32,
    _returned: *mut u32,
) -> u32 {
    // SAFETY: the caller's strings.
    let (image, option) = unsafe {
        (
            text(image).unwrap_or_default(),
            String::from_utf16_lossy(
                &crate::edge::wide_units(&crate::edge::InWStr::new(option))
                    .expect("the option name"),
            ),
        )
    };
    OPTIONS_ASKED.with(|asked| asked.borrow_mut().push((image, option)));
    STATUS_OBJECT_NAME_NOT_FOUND
}

/// RtlCreateProcessParameters, as ntdll lays the block out (`rtl::params`), on leaked host
/// memory: what a null string leaves out is the stand-in process's (its current directory; no
/// DLL path), the command line the image's path; what it was handed recorded.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn RtlCreateProcessParameters(
    parameters: *mut *mut ProcessParameters,
    image_path_name: *const UnicodeString,
    dll_path: *const UnicodeString,
    current_directory: *const UnicodeString,
    command_line: *const UnicodeString,
    environment: usize,
    window_title: *const UnicodeString,
    desktop_info: *const UnicodeString,
    shell_info: *const UnicodeString,
    runtime_data: *const UnicodeString,
) -> u32 {
    if let Some(status) = failing("RtlCreateProcessParameters") {
        return status;
    }
    // SAFETY: the caller's strings.
    let made = unsafe {
        MadeParameters {
            image_path_name: text(image_path_name).unwrap(),
            dll_path: text(dll_path),
            current_directory: text(current_directory),
            command_line: text(command_line),
            environment,
            window_title: text(window_title),
            desktop_info: text(desktop_info),
            shell_info: text(shell_info),
            runtime_data: bytes(runtime_data).map(<[u8]>::to_vec),
        }
    };
    PARAMETERS_MADE.with(|made_list| made_list.borrow_mut().push(made));
    let own_directory: Vec<u8> = super::files::CURRENT_DIRECTORY.with(|current| {
        current
            .borrow()
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect()
    });
    // SAFETY: as above.
    let strings = unsafe {
        let image = bytes(image_path_name).unwrap();
        rtl::params::Strings {
            current_directory: bytes(current_directory).unwrap_or(&own_directory),
            dll_path: bytes(dll_path).unwrap_or(&[]),
            image_path_name: image,
            command_line: bytes(command_line).unwrap_or(image),
            window_title: bytes(window_title),
            desktop_info: bytes(desktop_info),
            shell_info: bytes(shell_info),
            runtime_data: bytes(runtime_data),
        }
    };
    let header_size = core::mem::size_of::<ProcessParameters>();
    let block =
        std::boxed::Box::leak(std::vec![0u64; strings.block_size().div_ceil(8)].into_boxed_slice())
            .as_mut_ptr() as *mut u8;
    // SAFETY: a fresh block of the size: the structure, then the strings' room.
    unsafe {
        let header = &mut *(block as *mut ProcessParameters);
        let tail = core::slice::from_raw_parts_mut(block.add(header_size), strings.room());
        rtl::params::lay_out(header, tail, &strings, environment);
        parameters.write(header);
    }
    0
}

/// RtlDestroyProcessParameters: the block recorded as freed (its memory stays leaked).
pub unsafe extern "system" fn RtlDestroyProcessParameters(
    parameters: *mut ProcessParameters,
) -> u32 {
    PARAMETERS_DESTROYED.with(|destroyed| destroyed.borrow_mut().push(parameters as usize));
    0
}
