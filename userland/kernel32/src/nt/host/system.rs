//! The system information, virtual-memory, registry, section and clock stand-ins.

use std::cell::{Cell, RefCell};

use super::answer;

/// The performance counter's stand-in values.
pub const COUNTER: u64 = 0x1234_5678_9ABC;
pub const FREQUENCY: u64 = 1_193_182;

/// The stand-in machine: 0x4000 pages (64 MiB), 0x1000 of them free; the process reserving
/// [`VIRTUAL_SIZE`] bytes.
pub const PAGES: u32 = 0x4000;
pub const AVAILABLE: u32 = 0x1000;
pub const VIRTUAL_SIZE: u32 = 0x50_0000;

/// Dwords into the caller's buffer.
unsafe fn words(information: *mut u8, words: &[u32]) {
    for (at, word) in words.iter().enumerate() {
        // SAFETY: the caller's buffer, as long as the structure.
        unsafe { (information as *mut u32).add(at).write_unaligned(*word) };
    }
}

/// NtQuerySystemInformation, as the kernel answers it over the stand-in machine: the basic (0),
/// processor (1) and performance (2) information, and the time zone (44: no zone, a zero
/// structure), each at its size; the process listing (5) a test installed
/// ([`crate::nt::toolhelp`]).
pub unsafe extern "system" fn NtQuerySystemInformation(
    class: u32,
    information: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> u32 {
    let status = answer();
    if status != 0 {
        return status;
    }
    if class == 5 {
        // SAFETY: the caller's buffer and length.
        return unsafe { crate::nt::toolhelp::query(information, length, return_length) };
    }
    // SAFETY: the caller's buffer of `length` bytes.
    unsafe {
        information.write_bytes(0, length as usize);
        match (class, length) {
            (0, 44) => words(
                information,
                &[
                    0,
                    100_144,
                    0x1000,
                    PAGES,
                    1,
                    PAGES - 1,
                    0x1_0000,
                    0x1_0000,
                    0x7FFE_FFFF,
                    1,
                    1,
                ],
            ),
            (1, 12) => words(information, &[6 << 16]),
            (2, 0x138) => {
                let committed = PAGES - AVAILABLE;
                words(
                    information.add(0x2C),
                    &[AVAILABLE, committed, PAGES, committed],
                );
            }
            (44, 172) => {}
            _ => panic!("the stand-in answers classes 0, 1, 2 and 44 at their sizes"),
        }
    }
    0
}

std::thread_local! {
    /// The last virtual-memory or view call the stand-ins were handed: its base (a view's
    /// offset), size and the type or protection it asked for.
    pub static LAST_VM: Cell<Option<(usize, usize, u32)>> = const { Cell::new(None) };
    /// The last section creation: its access, protection, allocation attributes, file handle
    /// and maximum size (none for a null pointer).
    pub static LAST_SECTION: Cell<Option<(u32, u32, u32, u32, Option<i64>)>> = const { Cell::new(None) };
    /// The object name the last create or open stand-in was handed, and its root.
    pub static LAST_NAME: RefCell<Option<(u32, std::vec::Vec<u16>)>> = const { RefCell::new(None) };
    /// Every allocation, free and protection, in order: the service, the base and size it was
    /// handed, and the type or protection it asked for.
    pub static VM_CALLS: RefCell<std::vec::Vec<(&'static str, usize, usize, u32)>> = const { RefCell::new(std::vec::Vec::new()) };
}

/// The virtual-memory calls taken since the last look.
pub fn vm_calls() -> std::vec::Vec<(&'static str, usize, usize, u32)> {
    VM_CALLS.with(|calls| std::mem::take(&mut *calls.borrow_mut()))
}

/// The base the allocation and view stand-ins hand back.
pub const BASE: usize = 0x0034_0000;
/// The handle the create and open stand-ins hand out.
pub const HANDLE: u32 = 0x44;

pub unsafe extern "system" fn NtAllocateVirtualMemory(
    process: u32,
    base: *mut usize,
    _zero_bits: u32,
    size: *mut usize,
    kind: u32,
    protect: u32,
) -> u32 {
    if process == crate::nt::children::CHILD_PROCESS {
        // SAFETY: the caller's in/out values.
        return unsafe { crate::nt::children::allocate(&mut *base, &mut *size, kind, protect) };
    }
    // SAFETY: the caller's in/out values.
    unsafe {
        LAST_VM.with(|cell| cell.set(Some((base.read(), size.read(), kind))));
        VM_CALLS.with(|calls| {
            calls
                .borrow_mut()
                .push(("allocate", base.read(), size.read(), kind))
        });
        let status = answer();
        if status != 0 {
            return status;
        }
        base.write(BASE);
    }
    0
}

pub unsafe extern "system" fn NtFreeVirtualMemory(
    process: u32,
    base: *mut usize,
    size: *mut usize,
    kind: u32,
) -> u32 {
    if process == crate::nt::children::CHILD_PROCESS {
        // SAFETY: the caller's in/out values.
        return crate::nt::children::free(unsafe { base.read() }, kind);
    }
    // SAFETY: the caller's in/out values.
    LAST_VM.with(|cell| cell.set(Some(unsafe { (base.read(), size.read(), kind) })));
    VM_CALLS.with(|calls| {
        calls
            .borrow_mut()
            .push(("free", unsafe { base.read() }, unsafe { size.read() }, kind))
    });
    answer()
}

pub unsafe extern "system" fn NtProtectVirtualMemory(
    process: u32,
    base: *mut usize,
    size: *mut usize,
    protect: u32,
    old: *mut u32,
) -> u32 {
    if process == crate::nt::children::CHILD_PROCESS {
        // SAFETY: the caller's in/out values.
        return unsafe { crate::nt::children::protect(&mut *base, &mut *size, protect, &mut *old) };
    }
    // SAFETY: the caller's in/out values.
    LAST_VM.with(|cell| cell.set(Some(unsafe { (base.read(), size.read(), protect) })));
    VM_CALLS.with(|calls| {
        calls.borrow_mut().push((
            "protect",
            unsafe { base.read() },
            unsafe { size.read() },
            protect,
        ))
    });
    let status = answer();
    if status != 0 {
        return status;
    }
    // SAFETY: the caller's old protection.
    unsafe { old.write(4) };
    0
}

/// One MEMORY_BASIC_INFORMATION's 28 bytes.
pub unsafe extern "system" fn NtQueryVirtualMemory(
    _process: u32,
    address: usize,
    _class: u32,
    information: *mut u8,
    length: usize,
    returned: *mut usize,
) -> u32 {
    let status = answer();
    if status != 0 {
        return status;
    }
    if length < 28 {
        return rtl::status::STATUS_INFO_LENGTH_MISMATCH;
    }
    // SAFETY: the caller's structure and count.
    unsafe {
        words(
            information,
            &[
                address as u32 & !0xFFF,
                BASE as u32,
                4,
                0x1000,
                0x1000,
                4,
                0x2_0000,
            ],
        );
        returned.write(28);
    }
    0
}

/// A create or open: the name recorded, the handle handed out, the arranged status (an
/// informational one, STATUS_OBJECT_NAME_EXISTS, still hands the handle out).
pub(super) unsafe fn opened(
    handle: *mut u32,
    attributes: *const crate::nt::ObjectAttributes,
) -> u32 {
    // SAFETY: the caller's attributes and their name, when given.
    let name = unsafe {
        attributes.as_ref().and_then(|attributes| {
            attributes
                .object_name
                .as_ref()
                .map(|name| (attributes.root_directory, name.units().to_vec()))
        })
    };
    LAST_NAME.with(|cell| *cell.borrow_mut() = name);
    let status = answer();
    if status & 0x8000_0000 == 0 {
        // SAFETY: the caller's handle slot.
        unsafe { handle.write(HANDLE) };
    }
    status
}

std::thread_local! {
    /// The value NtQueryValueKey answers, as REG_SZ units (none: STATUS_OBJECT_NAME_NOT_FOUND),
    /// and the value names it was asked for.
    pub static KEY_VALUE: RefCell<Option<std::vec::Vec<u16>>> = const { RefCell::new(None) };
    pub static VALUE_NAMES: RefCell<std::vec::Vec<std::vec::Vec<u16>>> = const { RefCell::new(std::vec::Vec::new()) };
}

/// NtOpenKey: the name recorded, the handle handed out (see [`opened`]).
pub unsafe extern "system" fn NtOpenKey(
    key: *mut u32,
    _access: u32,
    attributes: *const crate::nt::ObjectAttributes,
) -> u32 {
    // SAFETY: the caller's arguments.
    unsafe { opened(key, attributes) }
}

/// NtQueryValueKey: [`KEY_VALUE`] as a KEY_VALUE_PARTIAL_INFORMATION (class 2 alone), its
/// size into the result length; STATUS_BUFFER_OVERFLOW when the buffer holds less.
pub unsafe extern "system" fn NtQueryValueKey(
    _key: u32,
    name: *const crate::nt::UnicodeString,
    class: u32,
    information: *mut u8,
    length: u32,
    result_length: *mut u32,
) -> u32 {
    assert_eq!(
        class, 2,
        "the stand-in answers KeyValuePartialInformation alone"
    );
    // SAFETY: the caller's name.
    VALUE_NAMES.with(|names| names.borrow_mut().push(unsafe { (*name).units() }.to_vec()));
    let status = answer();
    if status != 0 {
        return status;
    }
    let Some(mut data) = KEY_VALUE.with(|value| value.borrow().clone()) else {
        return 0xC000_0034;
    };
    data.push(0);
    let mut answer = std::vec::Vec::new();
    for word in [0u32, 1, 2 * data.len() as u32] {
        answer.extend_from_slice(&word.to_le_bytes());
    }
    for unit in data {
        answer.extend_from_slice(&unit.to_le_bytes());
    }
    // SAFETY: the caller's length slot and buffer, of `length` bytes.
    unsafe {
        result_length.write(answer.len() as u32);
        let fits = answer.len().min(length as usize);
        information.copy_from_nonoverlapping(answer.as_ptr(), fits);
        if fits < answer.len() {
            return 0x8000_0005;
        }
    }
    0
}

pub unsafe extern "system" fn NtCreateSection(
    handle: *mut u32,
    access: u32,
    attributes: *const crate::nt::ObjectAttributes,
    maximum: *const i64,
    protect: u32,
    allocation: u32,
    file: u32,
) -> u32 {
    // SAFETY: the caller's maximum size, when given.
    let maximum = (!maximum.is_null()).then(|| unsafe { maximum.read() });
    LAST_SECTION.with(|cell| cell.set(Some((access, protect, allocation, file, maximum))));
    if let Some(status) = crate::nt::children::failing("NtCreateSection") {
        return status;
    }
    if let (true, 0, Some(size)) = (crate::nt::toolhelp::backing(), file, maximum) {
        // SAFETY: the caller's handle slot.
        unsafe { handle.write(crate::nt::toolhelp::create_section(size as usize)) };
        return 0;
    }
    // SAFETY: the caller's arguments.
    unsafe { opened(handle, attributes) }
}

pub unsafe extern "system" fn NtOpenSection(
    handle: *mut u32,
    _access: u32,
    attributes: *const crate::nt::ObjectAttributes,
) -> u32 {
    // SAFETY: the caller's arguments.
    unsafe { opened(handle, attributes) }
}

pub unsafe extern "system" fn NtMapViewOfSection(
    section: u32,
    _process: u32,
    base: *mut usize,
    _zero_bits: u32,
    _commit_size: usize,
    offset: *mut i64,
    size: *mut usize,
    _inherit: u32,
    _allocation: u32,
    protect: u32,
) -> u32 {
    if crate::nt::toolhelp::backing() {
        return match crate::nt::toolhelp::map(section) {
            Ok((at, length)) => {
                // SAFETY: the caller's in/out values.
                unsafe { (base.write(at), size.write(length)) };
                0
            }
            Err(status) => status,
        };
    }
    // SAFETY: the caller's in/out values.
    LAST_VM.with(|cell| {
        cell.set(Some(unsafe {
            (offset.read() as usize, size.read(), protect)
        }))
    });
    let status = answer();
    if status != 0 {
        return status;
    }
    // SAFETY: as above.
    unsafe { base.write(BASE) };
    0
}

pub unsafe extern "system" fn NtUnmapViewOfSection(_process: u32, base: usize) -> u32 {
    LAST_VM.with(|cell| cell.set(Some((base, 0, 0))));
    answer()
}

/// NtQueryPerformanceCounter: the stand-in counter and, when asked, frequency.
pub unsafe extern "system" fn NtQueryPerformanceCounter(
    counter: *mut u64,
    frequency: *mut u64,
) -> u32 {
    let status = answer();
    if status != 0 {
        return status;
    }
    // SAFETY: the caller's counter and, when given, frequency.
    unsafe {
        counter.write(COUNTER);
        if !frequency.is_null() {
            frequency.write(FREQUENCY);
        }
    }
    0
}

std::thread_local! {
    /// The system times NtSetSystemTime set, in order.
    pub static TIMES_SET: RefCell<std::vec::Vec<u64>> = const { RefCell::new(std::vec::Vec::new()) };
}

/// NtSetSystemTime: the time kept (an arranged failure refuses it).
pub unsafe extern "system" fn NtSetSystemTime(time: *const u64, previous: *mut u64) -> u32 {
    let status = answer();
    if status != 0 {
        return status;
    }
    // SAFETY: the caller's time and, when given, previous time.
    unsafe {
        if !previous.is_null() {
            previous.write(0);
        }
        if !time.is_null() {
            TIMES_SET.with(|times| times.borrow_mut().push(time.read()));
        }
    }
    0
}
