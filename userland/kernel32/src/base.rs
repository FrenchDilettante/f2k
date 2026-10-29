//! The helpers kernel32's exports share, as Windows 2000's kernel32 names them: the calling
//! thread's last error, BaseSetLastNTError (a failed system service's status, mapped through
//! ntdll's RtlNtStatusToDosError), BaseFormatTimeOut, BaseFormatObjectAttributes and
//! BaseGetNamedObjectDirectory, the PEB lock's critical regions, the PEB, the process parameters,
//! the process heap and the environment block as the thread reaches them, the standard and console
//! handles' tests, and the A calls' strings converted through ntdll's code-page calls (in through
//! RtlAnsiStringToUnicodeString, out through RtlUnicodeToMultiByteN).

use rtl::params::{CountedString, ProcessParameters};
use rtl::peb::PebLdrData;
use rtl::sync::OnceWord;

use crate::heap::HeapArray;
use crate::nt::{self, ObjectAttributes, RtlBitmap, UnicodeString};
use crate::ntcall::FastPebLock;

/// kernel32's own data, as Windows 2000's kernel32 keeps it in its data section (every process its
/// own copy: its writable pages are copy-on-write): `fn name() -> &'static Type = init;` makes the
/// item and its accessor. On the host, each test thread is a process of its own (its own stand-in
/// PEB and TEB), so the item is one per test thread there.
macro_rules! own_data {
    ($(#[$meta:meta])* $vis:vis fn $name:ident() -> &'static $ty:ty = $init:expr;) => {
        $(#[$meta])*
        $vis fn $name() -> &'static $ty {
            #[cfg(not(test))]
            {
                static DATA: $ty = $init;
                &DATA
            }
            #[cfg(test)]
            {
                std::thread_local! {
                    static DATA: &'static $ty = std::boxed::Box::leak(std::boxed::Box::new($init));
                }
                DATA.with(|data| *data)
            }
        }
    };
}
pub(crate) use own_data;

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

/// A typed service's answer as a BOOL: TRUE when it succeeded, FALSE with the failed status's
/// error set (BaseSetLastNTError) otherwise.
pub fn win32_bool<T>(result: Result<T, u32>) -> u32 {
    match result {
        Ok(_) => 1,
        Err(status) => {
            set_last_nt_error(status);
            0
        }
    }
}

/// The current-process pseudo-handle (NtCurrentProcess).
pub const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
/// The current-thread pseudo-handle (NtCurrentThread).
pub const CURRENT_THREAD: u32 = 0xFFFF_FFFE;

/// INFINITE: the documented forever timeout.
pub const INFINITE: u32 = 0xFFFF_FFFF;

/// BaseFormatTimeOut: a Win32 timeout in milliseconds as the services' LARGE_INTEGER, a relative
/// interval (negative, in 100 ns units); none (forever) for INFINITE.
pub fn format_timeout(milliseconds: u32) -> Option<i64> {
    (milliseconds != INFINITE).then(|| -(i64::from(milliseconds) * 10_000))
}

/// OBJECT_ATTRIBUTES' Attributes: OBJ_INHERIT, OBJ_CASE_INSENSITIVE, OBJ_OPENIF.
pub const OBJ_INHERIT: u32 = 0x02;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const OBJ_OPENIF: u32 = 0x80;

/// The directory access kernel32 opens `\BaseNamedObjects` with: DIRECTORY_ALL_ACCESS less DELETE,
/// WRITE_DAC and WRITE_OWNER.
const NAMED_OBJECTS_ACCESS: u32 = 0x000F_000F & !0x000D_0000;

/// A UNICODE_STRING over the first `length` units of `units`, its room the whole buffer (see
/// [`UnicodeString::with_room`]).
///
/// # Panics
///
/// When `length` is past the buffer: the callers hand the units they wrote.
pub fn unicode_string(units: &mut [u16], length: usize) -> UnicodeString {
    UnicodeString::with_room(units, length).expect("a string past its buffer")
}

/// A UNICODE_STRING over a caller's NUL-terminated string, as RtlInitUnicodeString makes one: its
/// length to the terminator, its room the terminator's too (a string past the UNICODE_STRING's
/// limit stops at it: an assumption, unverified on the platform). The string stays where it is, at
/// any address: the services read it through the counted string.
///
/// # Safety
///
/// `string` points at a NUL-terminated UTF-16 string, aligned or not.
pub unsafe fn wide_string(string: *const u16) -> UnicodeString {
    const MOST_UNITS: usize = rtl::string::MAX_USTRING / 2 - 1;
    // SAFETY: the caller's string, read to its terminator.
    let units = unsafe { rtl::cstr::len_until_nul(string) }.min(MOST_UNITS);
    UnicodeString {
        length: (2 * units) as u16,
        maximum_length: (2 * units + 2) as u16,
        buffer: string.cast_mut(),
    }
}

/// A caller's UTF-16 string as [`wide_units`] reads it, its terminator left out: the caller's own
/// units where its pointer is aligned, a copy on the process heap where it is not.
pub enum WideUnits<'a> {
    Borrowed(&'a [u16]),
    Copied(HeapArray<u16>),
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
    // SAFETY: the caller's string, read to its terminator.
    let length = unsafe { rtl::cstr::len_until_nul(string) };
    // SAFETY: the `length` units the scan read.
    unsafe { wide_units_of(string, length) }
}

/// `length` UTF-16 units a caller passes at `units`, aligned or not, as [`wide_units`] reads a
/// string: borrowed where aligned, copied onto the process heap where not; none only when that
/// copy finds no room.
///
/// # Safety
///
/// `units` points at `length` readable UTF-16 units, aligned or not, unchanged for `'a`.
pub unsafe fn wide_units_of<'a>(units: *const u16, length: usize) -> Option<WideUnits<'a>> {
    if units.is_aligned() {
        // SAFETY: `length` units at an aligned address, the caller's for 'a (the contract).
        let units = unsafe { core::slice::from_raw_parts(units, length) };
        return Some(WideUnits::Borrowed(units));
    }
    let mut copy = HeapArray::new(length).ok()?;
    for (at, unit) in copy.iter_mut().enumerate() {
        // SAFETY: one of the caller's `length` units, read unaligned.
        *unit = unsafe { units.add(at).read_unaligned() };
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
    let mut ansi = nt::AnsiString::empty();
    let mut wide = unicode_string(buffer, 0);
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
    let _lock = crate::ntcall::PebLock::acquire();
    body()
}

own_data! {
    /// kernel32's `\BaseNamedObjects` handle (BaseNamedObjectDirectory).
    fn named_objects() -> &'static OnceWord<FastPebLock> = OnceWord::new(FastPebLock);
}

/// BaseGetNamedObjectDirectory: the handle to `\BaseNamedObjects` every named object is made in,
/// opened at the first need under the PEB lock and kept for the process's life; zero when it
/// cannot be opened (the named calls then fail on their name, and the next call tries again).
pub fn named_object_directory() -> u32 {
    named_objects().get_or_make(|| {
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
        let status =
            unsafe { nt::NtOpenDirectoryObject(&mut opened, NAMED_OBJECTS_ACCESS, &attributes) };
        if rtl::status::nt_success(status) {
            opened as usize
        } else {
            0
        }
    }) as u32
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
pub unsafe fn format_object_attributes<'a>(
    out: &'a mut ObjectAttributes,
    security: *const SecurityAttributes,
    name: Option<&UnicodeString>,
) -> Option<&'a ObjectAttributes> {
    if security.is_null() && name.is_none() {
        return None;
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
    Some(out)
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

/// The process parameters' standard handle `which` (0 to 2, as [`standard_slot`] names them).
pub fn parameters_standard_handle(which: usize) -> u32 {
    let parameters = process_parameters();
    // SAFETY: the process parameters, mapped for the process's whole life; the handle is read in
    // place (SetStdHandle writes it in place).
    let handle = unsafe {
        match which {
            0 => (&raw const (*parameters).standard_input).read_volatile(),
            1 => (&raw const (*parameters).standard_output).read_volatile(),
            _ => (&raw const (*parameters).standard_error).read_volatile(),
        }
    };
    handle as u32
}

/// Replace the process parameters' standard handle `which`.
pub fn set_parameters_standard_handle(which: usize, handle: u32) {
    let parameters = process_parameters();
    let handle = handle as usize;
    // SAFETY: as `parameters_standard_handle`'s; the handle is written in place, as Windows 2000's
    // SetStdHandle writes it.
    unsafe {
        match which {
            0 => (&raw mut (*parameters).standard_input).write_volatile(handle),
            1 => (&raw mut (*parameters).standard_output).write_volatile(handle),
            _ => (&raw mut (*parameters).standard_error).write_volatile(handle),
        }
    }
}

/// Change the process parameters' ConsoleFlags to `change`'s answer, under the PEB lock.
pub fn update_console_flags(change: impl FnOnce(u32) -> u32) {
    let parameters = process_parameters();
    under_peb_lock(|| {
        // SAFETY: the process parameters, mapped for the process's whole life; the flags are
        // read and written in place under the PEB lock.
        unsafe {
            let flags = &raw mut (*parameters).console_flags;
            flags.write_volatile(change(flags.read_volatile()));
        }
    });
}

/// The PEB's field, read in place.
macro_rules! peb_field {
    ($field:ident) => {
        // SAFETY: the PEB is mapped for the process's whole life (the host tests' stand-in for
        // theirs); its fields are read and written in place, one at a time, never borrowed whole.
        unsafe { (&raw const (*teb::peb()).$field).read_volatile() }
    };
}

/// The process image's base (the PEB's ImageBaseAddress).
pub fn image_base() -> usize {
    peb_field!(image_base_address)
}

/// The PEB's ProcessParameters (RTL_USER_PROCESS_PARAMETERS).
pub fn process_parameters() -> *mut ProcessParameters<usize> {
    peb_field!(process_parameters) as *mut ProcessParameters<usize>
}

/// The process heap (the PEB's ProcessHeap, which ntdll's LdrInitializeThunk makes).
pub fn process_heap() -> usize {
    peb_field!(process_heap)
}

/// The loader's module lists (the PEB's Ldr, a PEB_LDR_DATA).
pub fn loader_data() -> *const PebLdrData<usize> {
    peb_field!(ldr) as *const PebLdrData<usize>
}

/// The loader lock (the PEB's LoaderLock, the critical section ntdll's loader holds).
pub fn loader_lock() -> *mut u8 {
    peb_field!(loader_lock) as *mut u8
}

/// The TLS bitmaps' headers (the PEB's TlsBitmap and TlsExpansionBitmap, ntdll's RTL_BITMAPs).
pub fn tls_bitmaps() -> (*mut RtlBitmap, *mut RtlBitmap) {
    (
        peb_field!(tls_bitmap) as *mut RtlBitmap,
        peb_field!(tls_expansion_bitmap) as *mut RtlBitmap,
    )
}

/// The system's version, as the PEB records it.
#[derive(Clone, Copy, Debug)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub build: u16,
    /// OSCSDVersion: the service pack, its major number in the high byte.
    pub service_pack: u16,
    pub platform: u32,
}

/// The PEB's version fields.
pub fn version() -> Version {
    Version {
        major: peb_field!(os_major_version),
        minor: peb_field!(os_minor_version),
        build: peb_field!(os_build_number),
        service_pack: peb_field!(os_csd_version),
        platform: peb_field!(os_platform_id),
    }
}

/// The service pack's name (the PEB's CSDVersion).
pub fn csd_version() -> CountedString<usize> {
    peb_field!(csd_version)
}

/// A copy of the process parameters' fixed part (their strings' buffers stay where they are).
pub fn parameters() -> ProcessParameters<usize> {
    // SAFETY: the process parameters, mapped for the process's whole life, read in place.
    unsafe { process_parameters().read_volatile() }
}

/// The environment block (the process parameters' Environment: ntdll's to edit and move).
pub fn environment_block() -> *mut u16 {
    teb::environment_block()
}

/// The UTF-16 units of one of the process's own strings (the process parameters', the PEB's).
///
/// # Safety
///
/// The string's buffer holds its length, unchanged while the units are borrowed.
pub unsafe fn string_units<'a>(string: &CountedString<usize>) -> &'a [u16] {
    if string.length < 2 || string.buffer == 0 {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe {
        core::slice::from_raw_parts(string.buffer as *const u16, usize::from(string.length) / 2)
    }
}

/// The TEB's field, read in place: the calling thread's own.
macro_rules! teb_field {
    ($($field:tt)+) => {
        // SAFETY: the calling thread's TEB, mapped for its whole life (the host tests' stand-in for
        // theirs); its fields are read and written in place, never borrowed whole.
        unsafe { (&raw const (*teb::teb()).$($field)+).read_volatile() }
    };
}

/// Write the calling thread's TEB field in place.
macro_rules! set_teb_field {
    ($value:expr, $($field:tt)+) => {{
        let value = $value;
        // SAFETY: as `teb_field`'s: one of the calling thread's own fields.
        unsafe { (&raw mut (*teb::teb()).$($field)+).write_volatile(value) }
    }};
}

/// The calling thread's TLS slot `index` of its TEB's 64 (TlsSlots).
pub fn tls_slot(index: usize) -> usize {
    teb_field!(tls_slots[index])
}

/// Write the calling thread's TLS slot `index` of its TEB's 64.
pub fn set_tls_slot(index: usize, value: usize) {
    set_teb_field!(value, tls_slots[index])
}

/// The calling thread's TLS expansion slots' block (TlsExpansionSlots; null until made).
pub fn tls_expansion_slots() -> *mut usize {
    teb_field!(tls_expansion_slots) as *mut usize
}

/// The calling thread's locale (its TEB's CurrentLocale).
pub fn current_locale() -> u32 {
    teb_field!(current_locale)
}

/// Set the calling thread's locale.
pub fn set_current_locale(locale: u32) {
    set_teb_field!(locale, current_locale)
}

/// The calling thread's TEB and its process's PEB, through FS.
#[cfg(not(test))]
mod teb {
    use core::arch::asm;

    use rtl::peb::{Peb, Teb};

    /// The PEB (TEB+0x30).
    pub fn peb() -> *mut Peb<usize> {
        let peb: usize;
        // SAFETY: FS addresses the calling thread's TEB.
        unsafe {
            asm!("mov {peb}, dword ptr fs:[0x30]", peb = out(reg) peb,
                 options(nostack, readonly, preserves_flags))
        };
        peb as *mut Peb<usize>
    }

    /// The TEB (TEB+0x18, NT_TIB.Self).
    pub fn teb() -> *mut Teb<usize> {
        let teb: usize;
        // SAFETY: FS addresses the calling thread's TEB.
        unsafe {
            asm!("mov {teb}, dword ptr fs:[0x18]", teb = out(reg) teb,
                 options(nostack, readonly, preserves_flags))
        };
        teb as *mut Teb<usize>
    }

    pub fn environment_block() -> *mut u16 {
        // SAFETY: the process parameters, mapped for the process's whole life; the block's address
        // is read in place (ntdll moves the block under the PEB lock).
        unsafe {
            (&raw const (*super::process_parameters()).environment).read_volatile() as *mut u16
        }
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

/// The host tests' TEB: one per test thread, its PEB and process parameters the stand-in blocks
/// (`nt::threads`), laid out with the host's pointers.
#[cfg(test)]
mod teb {
    use std::cell::Cell;

    use rtl::peb::{Peb, Teb};

    std::thread_local! {
        static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
    }

    pub fn last_error() -> u32 {
        LAST_ERROR.with(Cell::get)
    }

    pub fn set_last_error(code: u32) {
        LAST_ERROR.with(|cell| cell.set(code))
    }

    pub fn peb() -> *mut Peb<usize> {
        crate::nt::threads::process().peb
    }

    pub fn teb() -> *mut Teb<usize> {
        crate::nt::threads::process().teb
    }

    /// The stand-in ntdll's environment block (`nt::host::ENVIRONMENT`).
    pub fn environment_block() -> *mut u16 {
        crate::nt::host::environment_block()
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
