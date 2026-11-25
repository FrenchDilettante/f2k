//! The helpers kernel32's exports share, as Windows 2000's kernel32 names them: the calling
//! thread's last error, BaseSetLastNTError (a failed system service's status, mapped through
//! ntdll's RtlNtStatusToDosError), BaseFormatTimeOut, BaseFormatObjectAttributes and
//! BaseGetNamedObjectDirectory, the PEB lock's critical regions, the PEB, the process parameters,
//! the process heap and the environment block as the thread reaches them, the standard and console
//! handles' tests, and a caller's UTF-16 string as kernel32 reads it ([`WideUnits`]: borrowed
//! where aligned, copied where not).

use rtl::cstr::ascii_units;
use rtl::params::{CountedString, ProcessParameters};
use rtl::sync::OnceWord;

use crate::edge::In;
use crate::heap::HeapArray;
use crate::nt::{ObjectAttributes, UnicodeString};
use crate::ntcall::{self, FastPebLock};

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
/// The calling thread's last error (its TEB's LastErrorValue), read and set.
pub use rtl::sys::{last_error, set_last_error};

/// BaseSetLastNTError: a failed system service's status, mapped to its Win32 error
/// (RtlNtStatusToDosError) and set as the last error; the error.
pub fn set_last_nt_error(status: u32) -> u32 {
    let error = ntcall::nt_status_to_dos_error(status);
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

// OBJECT_ATTRIBUTES' Attributes: OBJ_INHERIT, OBJ_CASE_INSENSITIVE, OBJ_OPENIF.
use rtl::nt::OBJ_OPENIF;
pub use rtl::nt::{OBJ_CASE_INSENSITIVE, OBJ_INHERIT};

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

/// A caller's UTF-16 string as [`crate::edge::wide_units`] reads it, its terminator left out: the
/// caller's own units where its pointer is aligned, a copy on the process heap where it is not.
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
        let mut name: [u16; 17] = ascii_units("\\BaseNamedObjects");
        let string = unicode_string(&mut name, 17);
        let attributes = ObjectAttributes {
            length: 24,
            root_directory: 0,
            object_name: &string,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: core::ptr::null(),
            security_quality_of_service: core::ptr::null(),
        };
        ntcall::open_directory_object(NAMED_OBJECTS_ACCESS, &attributes)
            .map_or(0, |opened| opened as usize)
    }) as u32
}

/// A SECURITY_ATTRIBUTES, as a create's caller passes it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecurityAttributes {
    pub length: u32,
    pub security_descriptor: *const u8,
    pub inherit_handle: u32,
}

/// BaseFormatObjectAttributes: the OBJECT_ATTRIBUTES a create passes — none when it has neither
/// security attributes nor a name; otherwise inheritable as the security attributes ask, and a
/// name is OBJ_OPENIF in `\BaseNamedObjects` (an existing object of the name is opened). The
/// attributes point at the name: they are used while it lives.
pub fn format_object_attributes(
    security: Option<In<'_, SecurityAttributes>>,
    name: Option<&UnicodeString>,
) -> Option<ObjectAttributes> {
    if security.is_none() && name.is_none() {
        return None;
    }
    let (mut attributes, descriptor) = match security.map(|security| security.read()) {
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
    Some(ObjectAttributes {
        length: 24,
        root_directory: root,
        object_name: name.map_or(core::ptr::null(), |name| name as *const UnicodeString),
        attributes,
        security_descriptor: descriptor,
        security_quality_of_service: core::ptr::null(),
    })
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

/// The process parameters' ConsoleFlags, read in place.
pub fn console_flags() -> u32 {
    let parameters = process_parameters();
    // SAFETY: the process parameters, mapped for the process's whole life; the flags are read in
    // place (SetConsoleCtrlHandler writes them in place).
    unsafe { (&raw const (*parameters).console_flags).read_volatile() }
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

/// The process parameters' ConsoleHandle replaced, in place: what CreateProcess left there for the
/// process's connection to its console (see `crate::console::connect_console`), and what the
/// process's children are started with.
pub fn set_console_handle(handle: usize) {
    let parameters = process_parameters();
    // SAFETY: the process parameters, mapped for the process's whole life; the handle is written
    // in place.
    unsafe { (&raw mut (*parameters).console_handle).write_volatile(handle) };
}

/// The PEB's fields kernel32 reads: the process image's base and subsystem, the process
/// parameters, and the system's version.
pub use rtl::sys::{image_base, image_subsystem, peb_version as version, process_parameters};

/// A copy of the process parameters' fixed part (their strings' buffers stay where they are).
pub fn parameters() -> ProcessParameters<usize> {
    // SAFETY: the process parameters, mapped for the process's whole life, read in place.
    unsafe { process_parameters().read_volatile() }
}

/// The environment block (the process parameters' Environment: ntdll's to edit and move).
#[cfg(not(test))]
pub fn environment_block() -> *mut u16 {
    // SAFETY: the process parameters, mapped for the process's whole life; the block's address is
    // read in place (ntdll moves the block under the PEB lock).
    unsafe { (&raw const (*process_parameters()).environment).read_volatile() as *mut u16 }
}

/// The host tests' environment block: the stand-in ntdll's (`nt::host::ENVIRONMENT`).
#[cfg(test)]
pub fn environment_block() -> *mut u16 {
    crate::nt::host::environment_block()
}

/// One of the process's own counted strings that kernel32 reads in place: the process parameters'
/// (their buffers inside the parameters' block) and the PEB's CSDVersion (the service pack's
/// name). Nothing rewrites them while the process runs (the parameters' current directory, which
/// changes, is not one of them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnString {
    CommandLine,
    ImagePathName,
    WindowTitle,
    DesktopInfo,
    ShellInfo,
    CsdVersion,
}

impl OwnString {
    /// The counted string itself: its lengths and its buffer's address (zero for none).
    pub fn counted(self) -> CountedString<usize> {
        match self {
            OwnString::CommandLine => parameters().command_line,
            OwnString::ImagePathName => parameters().image_path_name,
            OwnString::WindowTitle => parameters().window_title,
            OwnString::DesktopInfo => parameters().desktop_info,
            OwnString::ShellInfo => parameters().shell_info,
            OwnString::CsdVersion => rtl::sys::csd_version(),
        }
    }

    /// Its UTF-16 units, in place (none for a string without a unit or a buffer).
    pub fn units(self) -> &'static [u16] {
        // SAFETY: one of the process's own strings, as the process starts with it: its buffer
        // (in the process parameters' block, or where the PEB's CSDVersion points) holds its
        // length, mapped for the process's whole life, and nothing rewrites it.
        unsafe { self.counted().units() }
    }
}

/// The process's image path (its parameters' ImagePathName), as the loader's search reads it.
pub fn image_path_name() -> &'static [u16] {
    OwnString::ImagePathName.units()
}

/// The process's desktop (its parameters' DesktopInfo), as a new process inherits it.
pub fn desktop_info() -> &'static [u16] {
    OwnString::DesktopInfo.units()
}

/// The calling thread's TEB fields kernel32 reads and writes: its TLS slots, its process's id
/// and its locale.
pub use rtl::sys::{
    current_locale,
    current_process_id,
    set_current_locale,
    set_tls_slot,
    tls_slot,
};

/// The calling thread's TLS expansion slots' block (TlsExpansionSlots; null until made).
pub fn tls_expansion_slots() -> *mut usize {
    rtl::sys::tls_expansion_slots() as *mut usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::{wide_units, InWStr};
    use crate::nt;

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
        let aligned = wide_units(&unsafe { InWStr::new(storage.as_ptr()) }).unwrap();
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
        let unaligned = wide_units(&unsafe { InWStr::new(odd) }).unwrap();
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
