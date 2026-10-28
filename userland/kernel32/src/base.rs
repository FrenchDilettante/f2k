//! The helpers kernel32's exports share, as Windows 2000's kernel32 names them: the calling
//! thread's last error, BaseSetLastNTError (a failed system service's status, mapped through
//! ntdll's RtlNtStatusToDosError), BaseFormatTimeOut, BaseFormatObjectAttributes and
//! BaseGetNamedObjectDirectory, the PEB lock's critical regions, the PEB, the process parameters,
//! the process heap and the environment block as the thread reaches them, the standard and console
//! handles' tests, and the A calls' strings converted through ntdll's code-page calls (in through
//! RtlAnsiStringToUnicodeString, out through RtlUnicodeToMultiByteN).

use crate::nt::{self, ObjectAttributes, UnicodeString};

/// The calling thread's last error (TEB+0x34).
pub fn last_error() -> u32 {
    teb::last_error()
}

/// Set the calling thread's last error.
pub fn set_last_error(code: u32) {
    teb::set_last_error(code)
}

/// BaseSetLastNTError: a failed system service's status, mapped to its Win32 error
/// (RtlNtStatusToDosError) and set as the last error; the error.
pub fn set_last_nt_error(status: u32) -> u32 {
    // SAFETY: ntdll's export, callable with any status.
    let error = unsafe { nt::RtlNtStatusToDosError(status) };
    set_last_error(error);
    error
}

/// A system service's answer as a BOOL: TRUE for a success status, FALSE with the status's error
/// set (BaseSetLastNTError) otherwise.
pub fn succeeded(status: u32) -> u32 {
    if rtl::status::nt_success(status) {
        1
    } else {
        set_last_nt_error(status);
        0
    }
}

/// The current-process pseudo-handle (NtCurrentProcess).
pub const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
/// The current-thread pseudo-handle (NtCurrentThread).
pub const CURRENT_THREAD: u32 = 0xFFFF_FFFE;

/// INFINITE: the documented forever timeout.
pub const INFINITE: u32 = 0xFFFF_FFFF;

/// BaseFormatTimeOut: a Win32 timeout in milliseconds as the services' LARGE_INTEGER, a relative
/// interval (negative, in 100 ns units) in `out`; none (a null pointer: forever) for INFINITE.
pub fn format_timeout(milliseconds: u32, out: &mut i64) -> *const i64 {
    if milliseconds == INFINITE {
        return core::ptr::null();
    }
    *out = -(i64::from(milliseconds) * 10_000);
    out
}

/// OBJECT_ATTRIBUTES' Attributes: OBJ_INHERIT, OBJ_CASE_INSENSITIVE, OBJ_OPENIF.
pub const OBJ_INHERIT: u32 = 0x02;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const OBJ_OPENIF: u32 = 0x80;

/// The directory access kernel32 opens `\BaseNamedObjects` with: DIRECTORY_ALL_ACCESS less DELETE,
/// WRITE_DAC and WRITE_OWNER.
const NAMED_OBJECTS_ACCESS: u32 = 0x000F_000F & !0x000D_0000;

/// kernel32's `\BaseNamedObjects` handle's slot, on the PEB's page (Windows 2000 keeps it in
/// kernel32's data; F2K's system DLLs keep no writable data).
const NAMED_OBJECTS: usize = 0x880;

/// A UNICODE_STRING over the first `length` units of `units`.
pub fn unicode_string(units: &mut [u16], length: usize) -> UnicodeString {
    UnicodeString {
        length: (2 * length) as u16,
        maximum_length: (2 * units.len()) as u16,
        buffer: units.as_mut_ptr(),
    }
}

/// A UNICODE_STRING over a caller's NUL-terminated string, as RtlInitUnicodeString makes one: its
/// length to the terminator, its room the terminator's too (a string past the UNICODE_STRING's
/// limit stops at it: an assumption, unverified on the platform).
///
/// # Safety
///
/// `string` points at a NUL-terminated UTF-16 string.
pub unsafe fn wide_string(string: *const u16) -> UnicodeString {
    let mut units = 0usize;
    // SAFETY: the caller's string, read to its terminator.
    while units < 0x7FFE && unsafe { string.add(units).read() } != 0 {
        units += 1;
    }
    UnicodeString {
        length: (2 * units) as u16,
        maximum_length: (2 * units + 2) as u16,
        buffer: string as *mut u16,
    }
}

/// A caller's UTF-16 string as [`wide_units`] reads it, its terminator left out: the caller's own
/// units where its pointer is aligned, a copy on the process heap where it is not.
pub enum WideUnits<'a> {
    Borrowed(&'a [u16]),
    Copied(crate::create::HeapArray<u16>),
}

impl core::ops::Deref for WideUnits<'_> {
    type Target = [u16];

    fn deref(&self) -> &[u16] {
        match self {
            WideUnits::Borrowed(units) => units,
            WideUnits::Copied(units) => units,
        }
    }
}

/// A caller's NUL-terminated UTF-16 string, its terminator left out. An x86 program may hand an
/// LPCWSTR at an odd address, which Windows reads like any other; a Rust slice must be aligned, so
/// such a string is copied onto the process heap. None only when that copy finds no room.
///
/// # Safety
///
/// `string` points at a NUL-terminated UTF-16 string, aligned or not, that stays unchanged for
/// `'a` (a bad pointer faults the caller, as on the platform).
pub unsafe fn wide_units<'a>(string: *const u16) -> Option<WideUnits<'a>> {
    let mut length = 0;
    // SAFETY: the caller's string, read to its terminator; an unaligned read takes any address.
    while unsafe { string.add(length).read_unaligned() } != 0 {
        length += 1;
    }
    if string.is_aligned() {
        // SAFETY: the `length` units the loop read, at an aligned address, the caller's for 'a.
        let units = unsafe { core::slice::from_raw_parts(string, length) };
        return Some(WideUnits::Borrowed(units));
    }
    let mut copy = crate::create::HeapArray::new(length).ok()?;
    for (at, unit) in copy.iter_mut().enumerate() {
        // SAFETY: one of the units the loop read, unaligned.
        *unit = unsafe { string.add(at).read_unaligned() };
    }
    Some(WideUnits::Copied(copy))
}

/// An A call's narrow string converted into `buffer`, terminated, as Windows 2000's kernel32
/// converts one into a buffer of its own (the thread's static Unicode string, for a name): ntdll's
/// RtlInitAnsiString, then RtlAnsiStringToUnicodeString through the ANSI code page. Its length in
/// units; none when the buffer cannot hold it and its terminator (a null string is the empty one).
///
/// # Safety
///
/// `string` is null or a NUL-terminated string (a bad pointer faults the caller, as on the
/// platform).
pub unsafe fn ansi_into(string: *const u8, buffer: &mut [u16]) -> Option<usize> {
    let mut ansi = nt::AnsiString {
        length: 0,
        maximum_length: 0,
        buffer: core::ptr::null_mut(),
    };
    let mut wide = UnicodeString {
        length: 0,
        maximum_length: (2 * buffer.len()).min(rtl::string::MAX_USTRING) as u16,
        buffer: buffer.as_mut_ptr(),
    };
    // SAFETY: ntdll's exports, over the caller's string and the buffer, of the room given.
    let status = unsafe {
        nt::RtlInitAnsiString(&mut ansi, string);
        nt::RtlAnsiStringToUnicodeString(&mut wide, &ansi, 0)
    };
    rtl::status::nt_success(status).then_some(wide.length as usize / 2)
}

/// UTF-16 units narrowed through the ANSI code page into the bytes at `buffer`, as Windows 2000's
/// kernel32 hands an A call's strings back (ntdll's RtlUnicodeToMultiByteN). The code page is one
/// byte a character: `buffer` takes as many bytes as there are units.
///
/// # Safety
///
/// `buffer` holds `units.len()` bytes.
pub unsafe fn narrow(units: &[u16], buffer: *mut u8) {
    if units.is_empty() {
        return;
    }
    // SAFETY: ntdll's export, over the caller's buffer and the units, of the sizes given.
    unsafe {
        nt::RtlUnicodeToMultiByteN(
            buffer,
            units.len() as u32,
            core::ptr::null_mut(),
            units.as_ptr(),
            (2 * units.len()) as u32,
        )
    };
}

/// A caller's buffer for a string a call hands back: an A call's bytes (the units narrowed through
/// the ANSI code page, [`narrow`]) or a W call's UTF-16 units as they are. Code page 1252 is one
/// byte a character, so both count the same characters.
#[derive(Clone, Copy)]
pub enum Text {
    Ansi(*mut u8),
    Wide(*mut u16),
}

impl Text {
    pub fn is_null(self) -> bool {
        match self {
            Text::Ansi(buffer) => buffer.is_null(),
            Text::Wide(buffer) => buffer.is_null(),
        }
    }

    /// Write `units` from the buffer's start.
    ///
    /// # Safety
    ///
    /// The buffer holds them.
    pub unsafe fn put(self, units: &[u16]) {
        // SAFETY: the caller's contract.
        unsafe {
            match self {
                Text::Ansi(buffer) => narrow(units, buffer),
                Text::Wide(buffer) => {
                    for (at, &unit) in units.iter().enumerate() {
                        buffer.add(at).write_unaligned(unit);
                    }
                }
            }
        }
    }

    /// Write `units` from the buffer's start, then the terminator.
    ///
    /// # Safety
    ///
    /// The buffer holds them and the terminator.
    pub unsafe fn put_terminated(self, units: &[u16]) {
        // SAFETY: the caller's contract.
        unsafe {
            self.put(units);
            self.put_unit(units.len(), 0);
        }
    }

    /// Write one unit at character `at`.
    ///
    /// # Safety
    ///
    /// The buffer holds `at + 1` characters.
    pub unsafe fn put_unit(self, at: usize, unit: u16) {
        // SAFETY: the caller's contract.
        unsafe {
            match self {
                Text::Ansi(buffer) => narrow(&[unit], buffer.add(at)),
                Text::Wide(buffer) => buffer.add(at).write_unaligned(unit),
            }
        }
    }

    /// The address of the buffer's character `at` (a file part's place in it).
    pub fn address(self, at: usize) -> usize {
        match self {
            Text::Ansi(buffer) => buffer as usize + at,
            Text::Wide(buffer) => buffer as usize + 2 * at,
        }
    }
}

/// `body` under the PEB lock (RtlAcquirePebLock, RtlReleasePebLock): what serializes kernel32's
/// lazily made per-process state, as Windows 2000's kernel32 serializes it.
pub fn under_peb_lock<R>(body: impl FnOnce() -> R) -> R {
    // SAFETY: ntdll's export; the lock is the PEB's, free from the process's creation on.
    unsafe { nt::RtlAcquirePebLock() };
    let result = body();
    // SAFETY: as above; the caller holds it.
    unsafe { nt::RtlReleasePebLock() };
    result
}

/// BaseGetNamedObjectDirectory: the handle to `\BaseNamedObjects` every named object is made in,
/// opened at the first need under the PEB lock and kept for the process's life (PEB+0x880); zero
/// when it cannot be opened (the named calls then fail on their name).
pub fn named_object_directory() -> u32 {
    let slot = peb() + NAMED_OBJECTS;
    let handle = read(slot);
    if handle != 0 {
        return handle;
    }
    under_peb_lock(|| {
        if read(slot) == 0 {
            let mut name = [0u16; 17];
            for (unit, byte) in name.iter_mut().zip(b"\\BaseNamedObjects") {
                *unit = u16::from(*byte);
            }
            let string = unicode_string(&mut name, 17);
            let attributes = ObjectAttributes {
                length: 24,
                root_directory: 0,
                object_name: &string,
                attributes: OBJ_CASE_INSENSITIVE,
                security_descriptor: core::ptr::null(),
                security_quality_of_service: core::ptr::null(),
            };
            let mut opened = 0;
            // SAFETY: ntdll's export, over the attributes above.
            let status = unsafe {
                nt::NtOpenDirectoryObject(&mut opened, NAMED_OBJECTS_ACCESS, &attributes)
            };
            if rtl::status::nt_success(status) {
                write(slot, opened);
            }
        }
        read(slot)
    })
}

/// A SECURITY_ATTRIBUTES, as a create's caller passes it.
#[repr(C)]
pub struct SecurityAttributes {
    pub length: u32,
    pub security_descriptor: *const u8,
    pub inherit_handle: u32,
}

/// BaseFormatObjectAttributes: the OBJECT_ATTRIBUTES a create passes — none when it has neither
/// security attributes nor a name; otherwise inheritable as the security attributes ask, and a
/// name is OBJ_OPENIF in `\BaseNamedObjects` (an existing object of the name is opened).
///
/// # Safety
///
/// `security` is null or points at a SECURITY_ATTRIBUTES; `name` outlives the attributes' use.
pub unsafe fn format_object_attributes(
    out: &mut ObjectAttributes,
    security: *const SecurityAttributes,
    name: Option<&UnicodeString>,
) -> *const ObjectAttributes {
    if security.is_null() && name.is_none() {
        return core::ptr::null();
    }
    // SAFETY: the caller's structure, when given.
    let (mut attributes, descriptor) = match unsafe { security.as_ref() } {
        Some(security) => (
            if security.inherit_handle != 0 {
                OBJ_INHERIT
            } else {
                0
            },
            security.security_descriptor,
        ),
        None => (0, core::ptr::null()),
    };
    let mut root = 0;
    if name.is_some() {
        attributes |= OBJ_OPENIF;
        root = named_object_directory();
    }
    *out = ObjectAttributes {
        length: 24,
        root_directory: root,
        object_name: name.map_or(core::ptr::null(), |name| name as *const UnicodeString),
        attributes,
        security_descriptor: descriptor,
        security_quality_of_service: core::ptr::null(),
    };
    out
}

/// Whether a handle is a console handle (Windows 2000's CONSOLE_HANDLE: the low two bits set, bit
/// 28 clear, so INVALID_HANDLE_VALUE is not one). Console handles are not kernel handles: kernel32
/// routes them to the console server (see [`crate::console`]).
pub fn is_console_handle(handle: u32) -> bool {
    handle & 0x1000_0003 == 0x3
}

/// The standard handles' pseudo-values (STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE).
const STD_INPUT_HANDLE: u32 = -10i32 as u32;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;

/// Which of the process parameters' standard handles a pseudo-value names (0 StandardInput, 1
/// StandardOutput, 2 StandardError); none for any other value.
pub fn standard_slot(which: u32) -> Option<usize> {
    match which {
        STD_INPUT_HANDLE => Some(0),
        STD_OUTPUT_HANDLE => Some(1),
        STD_ERROR_HANDLE => Some(2),
        _ => None,
    }
}

/// A handle as the file calls take it: a standard handle's pseudo-value is the process parameters'
/// StandardInput, StandardOutput or StandardError, as Windows 2000's ReadFile and WriteFile read
/// it.
pub fn standard_handle(handle: u32) -> u32 {
    standard_slot(handle).map_or(handle, parameters_standard_handle)
}

/// The process parameters' StandardInput, then StandardOutput and StandardError.
const STANDARD_INPUT: usize = 0x18;

/// The process parameters' standard handle `which` (0 to 2, as [`standard_slot`] names them).
pub fn parameters_standard_handle(which: usize) -> u32 {
    read(process_parameters() + STANDARD_INPUT + 4 * which)
}

/// Replace the process parameters' standard handle `which`.
pub fn set_parameters_standard_handle(which: usize, handle: u32) {
    write(process_parameters() + STANDARD_INPUT + 4 * which, handle)
}

/// The calling process's PEB, by its address (the host tests' stand-in page there).
pub fn peb() -> usize {
    teb::peb()
}

/// The calling thread's TEB, by its address (the host tests' stand-in page there).
pub fn teb_address() -> usize {
    teb::teb()
}

/// The PEB's ProcessParameters (RTL_USER_PROCESS_PARAMETERS).
pub fn process_parameters() -> usize {
    read_pointer(peb() + 0x10)
}

/// The process heap (the PEB's ProcessHeap, which ntdll's LdrInitializeThunk makes).
pub fn process_heap() -> usize {
    read_pointer(peb() + 0x18)
}

/// The environment block (the process parameters' Environment: ntdll's to edit and move).
pub fn environment_block() -> *mut u16 {
    teb::environment_block()
}

/// The dword at `at` in the PEB, the TEB or a block they point at.
pub fn read(at: usize) -> u32 {
    // SAFETY: the callers read the TEB, the PEB and the process parameters, mapped for the
    // thread's or the process's whole life.
    unsafe { (at as *const u32).read_volatile() }
}

/// Write the dword at `at` in the PEB, the TEB or a block they point at.
pub fn write(at: usize, value: u32) {
    // SAFETY: as `read`; the callers write their own slots.
    unsafe { (at as *mut u32).write_volatile(value) }
}

/// The pointer at `at` in the PEB, the TEB or a block they point at (a dword on the target; the
/// host tests keep their 64-bit pointers beside the stand-in pages).
pub fn read_pointer(at: usize) -> usize {
    teb::read_pointer(at)
}

/// Write the pointer at `at` in the PEB, the TEB or a block they point at.
pub fn write_pointer(at: usize, value: usize) {
    teb::write_pointer(at, value)
}

/// The UTF-16 units of the UNICODE_STRING at `at`.
///
/// # Safety
///
/// `at` addresses a UNICODE_STRING whose buffer holds its length (the process's own strings).
pub unsafe fn units<'a>(at: usize) -> &'a [u16] {
    let length = read(at) & 0xFFFF;
    let buffer = read_pointer(at + 4);
    if length == 0 || buffer == 0 {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts(buffer as *const u16, length as usize / 2) }
}

/// The calling thread's TEB fields kernel32 reads and writes, and its process's PEB.
#[cfg(not(test))]
mod teb {
    use core::arch::asm;

    /// The PEB (TEB+0x30).
    pub fn peb() -> usize {
        let peb: usize;
        // SAFETY: FS addresses the calling thread's TEB.
        unsafe {
            asm!("mov {peb}, dword ptr fs:[0x30]", peb = out(reg) peb,
                 options(nostack, readonly, preserves_flags))
        };
        peb
    }

    /// The TEB (TEB+0x18, NT_TIB.Self).
    pub fn teb() -> usize {
        let teb: usize;
        // SAFETY: FS addresses the calling thread's TEB.
        unsafe {
            asm!("mov {teb}, dword ptr fs:[0x18]", teb = out(reg) teb,
                 options(nostack, readonly, preserves_flags))
        };
        teb
    }

    pub fn read_pointer(at: usize) -> usize {
        super::read(at) as usize
    }

    pub fn environment_block() -> *mut u16 {
        read_pointer(super::process_parameters() + 0x48) as *mut u16
    }

    pub fn write_pointer(at: usize, value: usize) {
        super::write(at, value as u32)
    }

    pub fn last_error() -> u32 {
        let code: u32;
        // SAFETY: FS addresses the calling thread's TEB; LastErrorValue is at 34h.
        unsafe {
            asm!("mov {code}, dword ptr fs:[0x34]", code = out(reg) code,
                 options(nostack, readonly, preserves_flags))
        };
        code
    }

    pub fn set_last_error(code: u32) {
        // SAFETY: as above.
        unsafe {
            asm!("mov dword ptr fs:[0x34], {code}", code = in(reg) code,
                 options(nostack, preserves_flags))
        };
    }
}

/// The host tests' TEB: one per test thread, its PEB and process parameters the stand-in pages
/// (`nt::threads`).
#[cfg(test)]
mod teb {
    use std::cell::{Cell, RefCell};

    std::thread_local! {
        static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
        /// The pointer fields written, by address: the host's pointers do not fit the target's
        /// dwords.
        static POINTERS: RefCell<std::collections::HashMap<usize, usize>> =
            RefCell::new(std::collections::HashMap::new());
    }

    pub fn last_error() -> u32 {
        LAST_ERROR.with(Cell::get)
    }

    pub fn set_last_error(code: u32) {
        LAST_ERROR.with(|cell| cell.set(code))
    }

    pub fn peb() -> usize {
        crate::nt::threads::process().peb
    }

    pub fn teb() -> usize {
        crate::nt::threads::process().teb
    }

    /// The stand-in ntdll's environment block (`nt::host::ENVIRONMENT`).
    pub fn environment_block() -> *mut u16 {
        crate::nt::host::environment_block()
    }

    pub fn read_pointer(at: usize) -> usize {
        POINTERS
            .with(|pointers| pointers.borrow().get(&at).copied())
            .unwrap_or(0)
    }

    pub fn write_pointer(at: usize, value: usize) {
        POINTERS.with(|pointers| pointers.borrow_mut().insert(at, value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failed service's status becomes the last error through RtlNtStatusToDosError
    /// (STATUS_INVALID_HANDLE is ERROR_INVALID_HANDLE, STATUS_ACCESS_VIOLATION ERROR_NOACCESS).
    #[test]
    fn a_failed_status_sets_its_win32_error() {
        assert_eq!(set_last_nt_error(0xC000_0008), 6);
        assert_eq!(last_error(), 6);
        assert_eq!(set_last_nt_error(0xC000_0005), 998);
        assert_eq!(last_error(), 998);
        set_last_error(0);
        assert_eq!(last_error(), 0);
        assert_eq!((succeeded(0), last_error()), (1, 0));
        assert_eq!((succeeded(0xC000_0008), last_error()), (0, 6));
    }

    /// A caller's string reads alike at any address: an aligned one is the caller's own units, an
    /// unaligned one (an x86 program may pass one) a copy.
    #[test]
    fn wide_units_reads_an_unaligned_string() {
        let text: Vec<u16> = "C:\\F2K\\KID.EXE".encode_utf16().collect();
        let mut storage = [0u16; 32];
        storage[..text.len()].copy_from_slice(&text);
        // SAFETY: a NUL-terminated string in `storage`, aligned.
        let aligned = unsafe { wide_units(storage.as_ptr()) }.unwrap();
        assert!(matches!(aligned, WideUnits::Borrowed(_)));
        assert_eq!(*aligned, text[..]);
        #[repr(align(2))]
        struct Even([u8; 64]);
        let mut bytes = Even([0; 64]);
        for (at, unit) in text.iter().enumerate() {
            bytes.0[1 + 2 * at..3 + 2 * at].copy_from_slice(&unit.to_le_bytes());
        }
        let odd = bytes.0[1..].as_ptr() as *const u16;
        assert!(!odd.is_aligned());
        // SAFETY: a NUL-terminated string in `bytes` (zeroed past the text), at an odd address.
        let unaligned = unsafe { wide_units(odd) }.unwrap();
        assert!(matches!(unaligned, WideUnits::Copied(_)));
        assert_eq!(*unaligned, text[..]);
    }

    /// The stand-ins record their calls and fail on demand.
    #[test]
    fn the_stand_ins_fail_on_demand() {
        // SAFETY: the host stand-in.
        assert_eq!(unsafe { nt::NtClose(0x44) }, 0);
        nt::FAIL_NEXT.with(|fail| fail.set(0xC000_0008));
        // SAFETY: as above.
        assert_eq!(unsafe { nt::NtClose(0x48) }, 0xC000_0008);
        assert_eq!(unsafe { nt::NtClose(0x4C) }, 0, "one failure only");
        nt::CLOSED.with(|closed| assert_eq!(*closed.borrow(), [0x44, 0x48, 0x4C]));
    }

    /// Console handles are the low-two-bit values below bit 28; the standard pseudo-values name
    /// the parameters' handles (the captured 3, 7 and 0xB), anything else itself.
    #[test]
    fn console_and_standard_handles() {
        for handle in [3, 7, 0xB, 0xF, 0x0FFF_FFFF] {
            assert!(is_console_handle(handle), "{handle:#x}");
        }
        for handle in [0, 4, 0x44, 0xFFFF_FFFF, 0x1000_0003] {
            assert!(!is_console_handle(handle), "{handle:#x}");
        }
        assert_eq!(standard_handle(-10i32 as u32), 3);
        assert_eq!(standard_handle(-11i32 as u32), 7);
        assert_eq!(standard_handle(-12i32 as u32), 0xB);
        assert_eq!(standard_handle(0x44), 0x44);
        assert_eq!(standard_slot(-13i32 as u32), None);
    }
}
