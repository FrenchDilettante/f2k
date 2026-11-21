//! advapi32's seam to the other system DLLs: what its code calls, imported by name as Windows
//! 2000's advapi32 imports it (ntdll and kernel32), and the memory probe its stub routine reads
//! arguments through (its import table holds no memory query). The host tests replace the imports
//! with stand-ins of the same shape ([`host`]).
//!
//! Each import is wrapped once here in a safe function over references and slices, a service's
//! failure an `Err` of its status; the only `unsafe` the rest of the DLL's code reaches for an
//! import is here. The strings and blocks the services take are types that hold what they point
//! at: [`Counted`] (a UNICODE_STRING over borrowed units), [`Wide`] (one a conversion allocated),
//! [`HeapBlock`] (a block of the process heap) and [`KeyAttributes`] (an OBJECT_ATTRIBUTES naming a
//! key). The caller's memory a token service reads or writes for an export's caller is handed
//! through as its address ([`Passed`]), which the service probes.

use core::ffi::CStr;
use core::marker::PhantomData;

use rtl::heap::HEAP_ZERO_MEMORY;
use rtl::status::{checked, NtStatus};
use rtl::string::{AnsiString, UnicodeString};

/// An OBJECT_ATTRIBUTES (`rtl::nt`'s) as the key services read it: its name and security pointers
/// the process's own.
type ObjectAttributes = rtl::nt::ObjectAttributes<u32, *const UnicodeString, *const u8>;

#[cfg(all(target_arch = "x86", not(test)))]
mod raw {
    use super::{AnsiString, ObjectAttributes, UnicodeString};

    #[link(
        name = "kernel32",
        kind = "raw-dylib",
        import_name_type = "undecorated"
    )]
    unsafe extern "system" {
        /// SetLastError: the calling thread's last error.
        pub fn SetLastError(code: u32);
        /// RaiseException: an exception raised with the code, flags and arguments (a
        /// noncontinuable one does not return).
        pub fn RaiseException(code: u32, flags: u32, count: u32, arguments: *const usize);
        /// GetComputerNameW: the computer's name and its terminator into the buffer of the size's
        /// characters, the size then its length.
        pub fn GetComputerNameW(buffer: *mut u16, size: *mut u32) -> u32;
    }

    #[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "C" {
        /// DbgPrint: the text the format makes, to the debugger (F2K: COM1, as `F2K: debug:`
        /// lines).
        pub fn DbgPrint(format: *const u8, ...) -> u32;
    }

    #[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        /// NtCreateKey: the key the attributes name, made when its last name is missing; its
        /// handle, and whether it was made (REG_CREATED_NEW_KEY) or opened
        /// (REG_OPENED_EXISTING_KEY).
        pub fn NtCreateKey(
            key: *mut u32,
            desired_access: u32,
            attributes: *const ObjectAttributes,
            title_index: u32,
            class: *const UnicodeString,
            options: u32,
            disposition: *mut u32,
        ) -> u32;
        /// NtOpenKey: the key the attributes name, its handle.
        pub fn NtOpenKey(
            key: *mut u32,
            desired_access: u32,
            attributes: *const ObjectAttributes,
        ) -> u32;
        /// NtDeleteKey: the key the handle names deleted (not one with subkeys).
        pub fn NtDeleteKey(key: u32) -> u32;
        /// NtEnumerateKey: a subkey's information of a class, by its place in the key's listing.
        pub fn NtEnumerateKey(
            key: u32,
            index: u32,
            class: u32,
            information: *mut u8,
            length: u32,
            result_length: *mut u32,
        ) -> u32;
        /// NtEnumerateValueKey: a value's information of a class, by its place in the key's
        /// listing.
        pub fn NtEnumerateValueKey(
            key: u32,
            index: u32,
            class: u32,
            information: *mut u8,
            length: u32,
            result_length: *mut u32,
        ) -> u32;
        /// NtQueryKey: the key's own information of a class.
        pub fn NtQueryKey(
            key: u32,
            class: u32,
            information: *mut u8,
            length: u32,
            result_length: *mut u32,
        ) -> u32;
        /// NtQueryValueKey: a value's information of a class, by its name.
        pub fn NtQueryValueKey(
            key: u32,
            name: *const UnicodeString,
            class: u32,
            information: *mut u8,
            length: u32,
            result_length: *mut u32,
        ) -> u32;
        /// NtSetValueKey: a value set, by its name, to the data and type given.
        pub fn NtSetValueKey(
            key: u32,
            name: *const UnicodeString,
            title_index: u32,
            kind: u32,
            data: *const u8,
            size: u32,
        ) -> u32;
        /// NtClose: the handle closed.
        pub fn NtClose(handle: u32) -> u32;
        /// NtOpenProcessToken: a handle to the token of the process the handle names.
        pub fn NtOpenProcessToken(process: u32, access: u32, token: *mut u32) -> u32;
        /// NtAdjustPrivilegesToken: the token's privileges enabled or disabled as the new state
        /// says (or all disabled), what changed reported in the previous state.
        pub fn NtAdjustPrivilegesToken(
            token: u32,
            disable_all: u8,
            new_state: *const u8,
            length: u32,
            previous_state: *mut u8,
            return_length: *mut u32,
        ) -> u32;
        /// NtQueryInformationToken: the token's information of a class.
        pub fn NtQueryInformationToken(
            token: u32,
            class: u32,
            information: *mut u8,
            length: u32,
            return_length: *mut u32,
        ) -> u32;
        /// NtDuplicateToken: a copy of the token, of the type given (an impersonation token at
        /// the attributes' quality of service's level), its handle opened with the access.
        pub fn NtDuplicateToken(
            token: u32,
            access: u32,
            attributes: *const ObjectAttributes,
            effective_only: u8,
            kind: u32,
            duplicate: *mut u32,
        ) -> u32;
        /// RtlOpenCurrentUser: the current user's hive, HKEY_CURRENT_USER's key.
        pub fn RtlOpenCurrentUser(desired_access: u32, key: *mut u32) -> u32;
        /// RtlNtStatusToDosError: the Win32 error an NTSTATUS maps to.
        pub fn RtlNtStatusToDosError(status: u32) -> u32;
        /// RtlAnsiStringToUnicodeString: the ANSI string converted (into a process-heap buffer
        /// when asked to allocate it, which RtlFreeUnicodeString frees).
        pub fn RtlAnsiStringToUnicodeString(
            destination: *mut UnicodeString,
            source: *const AnsiString,
            allocate: u32,
        ) -> u32;
        /// RtlUnicodeStringToAnsiString: the Unicode string converted (into the destination's own
        /// buffer: what fits, terminated, STATUS_BUFFER_OVERFLOW when not the whole).
        pub fn RtlUnicodeStringToAnsiString(
            destination: *mut AnsiString,
            source: *const UnicodeString,
            allocate: u32,
        ) -> u32;
        pub fn RtlFreeUnicodeString(string: *mut UnicodeString);
        /// RtlUnicodeToMultiByteN, RtlMultiByteToUnicodeN and RtlUnicodeToMultiByteSize: the ANSI
        /// code page's conversions of counted buffers.
        pub fn RtlUnicodeToMultiByteN(
            multi_byte: *mut u8,
            max_bytes: u32,
            bytes_written: *mut u32,
            unicode: *const u16,
            unicode_bytes: u32,
        ) -> u32;
        pub fn RtlMultiByteToUnicodeN(
            unicode: *mut u16,
            max_bytes: u32,
            bytes_written: *mut u32,
            multi_byte: *const u8,
            multi_byte_bytes: u32,
        ) -> u32;
        pub fn RtlUnicodeToMultiByteSize(
            bytes: *mut u32,
            unicode: *const u16,
            unicode_bytes: u32,
        ) -> u32;
        /// RtlAllocateHeap and RtlFreeHeap: a heap's blocks (advapi32's are the process heap's).
        pub fn RtlAllocateHeap(heap: usize, flags: u32, size: usize) -> *mut u8;
        pub fn RtlFreeHeap(heap: usize, flags: u32, block: *mut u8) -> u32;
    }

    /// The process heap (the PEB's ProcessHeap).
    pub fn process_heap() -> usize {
        rtl::sys::process_heap_handle()
    }
}

#[cfg(test)]
use host as raw;
#[cfg(test)]
pub use host::Probed;
/// The caller's memory as the stub routine reads it: probed byte by byte.
#[cfg(all(target_arch = "x86", not(test)))]
pub use rtl::probe::Probed;

// --- The strings, the blocks and the attributes the services take
// ----------------------------------

/// A counted string over units borrowed for `'a`: the UNICODE_STRING the services are handed, its
/// buffer the units' (null for none), so it holds its length while it lives.
#[derive(Clone, Copy)]
pub struct Counted<'a> {
    string: UnicodeString,
    units: &'a [u16],
}

impl<'a> Counted<'a> {
    /// The string over `units`: their first 32766 (a counted string's length is a word of bytes,
    /// kept even).
    pub fn new(units: &'a [u16]) -> Self {
        let units = &units[..units.len().min(0xFFFC / 2)];
        let bytes = 2 * units.len() as u16;
        Counted {
            string: UnicodeString {
                length: bytes,
                maximum_length: bytes,
                buffer: if units.is_empty() {
                    core::ptr::null_mut()
                } else {
                    units.as_ptr().cast_mut()
                },
            },
            units,
        }
    }

    /// The string's units.
    pub fn units(&self) -> &'a [u16] {
        self.units
    }

    /// Whether the string is empty.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }
}

/// An ANSI string converted to Unicode by RtlAnsiStringToUnicodeString: its buffer the process
/// heap's, its terminator past its length, freed by RtlFreeUnicodeString when dropped.
pub struct Wide {
    string: UnicodeString,
}

impl Wide {
    /// The string as the services take it.
    pub fn counted(&self) -> Counted<'_> {
        // SAFETY: the conversion's buffer holds the string's length, aligned (a heap block); it
        // lives, unchanged, until the drop.
        Counted::new(unsafe { self.string.units() })
    }

    /// The string's bytes and its terminator's.
    pub fn terminated_bytes(&self) -> &[u8] {
        let length = (usize::from(self.string.length) + 2).min(self.string.maximum_length.into());
        // SAFETY: the conversion allocated the string and its terminator (its room), and wrote
        // both; the block lives until the drop.
        unsafe { core::slice::from_raw_parts(self.string.buffer.cast(), length) }
    }
}

impl Drop for Wide {
    fn drop(&mut self) {
        // SAFETY: the string RtlAnsiStringToUnicodeString allocated, freed once.
        unsafe { raw::RtlFreeUnicodeString(&mut self.string) };
    }
}

/// The process heap, through this DLL's imports (RtlAllocateHeap and RtlFreeHeap on the PEB's
/// ProcessHeap).
pub struct ProcessHeap;

impl rtl::heap::ProcessHeap for ProcessHeap {
    fn allocate(size: usize) -> *mut u8 {
        // SAFETY: a plain allocation.
        unsafe { raw::RtlAllocateHeap(raw::process_heap(), HEAP_ZERO_MEMORY, size) }
    }

    unsafe fn free(block: *mut u8) {
        // SAFETY: the caller's contract: a block of the process heap this DLL took, freed once.
        unsafe { raw::RtlFreeHeap(raw::process_heap(), 0, block) };
    }
}

/// A zeroed block of the process heap, freed when dropped.
pub type HeapBlock = rtl::heap::Block<ProcessHeap>;

/// The OBJECT_ATTRIBUTES the key services are handed: a name below a root key (zero: an absolute
/// name) and the OBJ_* attributes, with no security descriptor or quality of service. The name
/// lives as long as the attributes do.
pub struct KeyAttributes<'a> {
    raw: ObjectAttributes,
    name: PhantomData<&'a UnicodeString>,
}

impl<'a> KeyAttributes<'a> {
    /// The attributes naming `name` below `root`.
    pub fn new(root: u32, name: &'a Counted<'_>, attributes: u32) -> Self {
        KeyAttributes {
            raw: ObjectAttributes {
                length: core::mem::size_of::<ObjectAttributes>() as u32,
                root_directory: root,
                object_name: &name.string,
                attributes,
                security_descriptor: core::ptr::null(),
                security_quality_of_service: core::ptr::null(),
            },
            name: PhantomData,
        }
    }
}

/// A caller's memory the kernel reads or writes for it, handed through as its address (null for
/// none): the service probes it, and advapi32 itself never touches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Passed(usize);

impl Passed {
    /// No memory: a null pointer.
    pub const NONE: Passed = Passed(0);

    /// The caller's memory at `address`.
    ///
    /// # Safety
    ///
    /// `address` is what the export's caller passed for the service to read or write under the
    /// API's contract (or an address it cannot reach, which the service refuses): nothing of
    /// advapi32's own lives there.
    pub unsafe fn new(address: usize) -> Self {
        Passed(address)
    }
}

// --- kernel32
// ----------------------------------------------------------------------------------------

/// SetLastError: the calling thread's last error.
pub fn set_last_error(code: u32) {
    // SAFETY: no pointers; it writes the thread's own TEB.
    unsafe { raw::SetLastError(code) }
}

/// RaiseException: `code` raised with `flags` and `arguments` (a noncontinuable exception does not
/// return to its raiser).
pub fn raise_exception(code: u32, flags: u32, arguments: &[usize]) {
    // SAFETY: the call reads the arguments' count of them.
    unsafe { raw::RaiseException(code, flags, arguments.len() as u32, arguments.as_ptr()) }
}

/// GetComputerNameW: the computer's name into `buffer`: its length (the terminator written after
/// it), or none when it does not fit (or cannot be read).
pub fn computer_name(buffer: &mut [u16]) -> Option<usize> {
    let mut size = buffer.len() as u32;
    // SAFETY: the call writes at most the buffer's size of characters into it, and the length
    // into the local.
    let ok = unsafe { raw::GetComputerNameW(buffer.as_mut_ptr(), &mut size) };
    (ok != 0).then_some(size as usize)
}

// --- ntdll -------------------------------------------------------------------------------------------

/// DbgPrint of `text`, as is (through `"%s"`).
pub fn debug_print(text: &CStr) {
    // SAFETY: the format and the text are NUL-terminated; the format takes the one string.
    unsafe { raw::DbgPrint(c"%s".as_ptr().cast(), text.as_ptr().cast::<u8>()) };
}

/// RtlNtStatusToDosError: the Win32 error `status` maps to.
pub fn dos_error(status: NtStatus) -> u32 {
    // SAFETY: no pointers.
    unsafe { raw::RtlNtStatusToDosError(status.0) }
}

/// RtlOpenCurrentUser: the current user's hive, opened with `access`.
pub fn open_current_user(access: u32) -> Result<u32, NtStatus> {
    let mut key = 0u32;
    // SAFETY: the call writes the handle into the local.
    checked(unsafe { raw::RtlOpenCurrentUser(access, &mut key) })?;
    Ok(key)
}

/// NtOpenKey: the key `attributes` name, opened with `access`.
pub fn open_key(attributes: &KeyAttributes, access: u32) -> Result<u32, NtStatus> {
    let mut key = 0u32;
    // SAFETY: the attributes and their name live across the call; the handle goes into the local.
    checked(unsafe { raw::NtOpenKey(&mut key, access, &attributes.raw) })?;
    Ok(key)
}

/// NtCreateKey: the key `attributes` name, made (of `class`, with `options`) when its last name is
/// missing, opened with `access`: its handle and the disposition.
pub fn create_key(
    attributes: &KeyAttributes,
    access: u32,
    class: Option<&Counted>,
    options: u32,
) -> Result<(u32, u32), NtStatus> {
    let (mut key, mut disposition) = (0u32, 0u32);
    let class = class.map_or(core::ptr::null(), |class| {
        &class.string as *const UnicodeString
    });
    // SAFETY: the attributes, their name and the class live across the call; the handle and the
    // disposition go into the locals.
    checked(unsafe {
        raw::NtCreateKey(
            &mut key,
            access,
            &attributes.raw,
            0,
            class,
            options,
            &mut disposition,
        )
    })?;
    Ok((key, disposition))
}

/// NtDeleteKey: the key `key` names deleted.
pub fn delete_key(key: u32) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtDeleteKey(key) })
}

/// NtClose: `handle` closed.
pub fn close(handle: u32) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtClose(handle) })
}

/// NtOpenProcessToken: a handle to the token of the process `process` names, opened with
/// `access`, written to the caller's `token`.
pub fn open_process_token(process: u32, access: u32, token: Passed) -> Result<(), NtStatus> {
    // SAFETY: the one place the service writes is the caller's, which it probes.
    checked(unsafe { raw::NtOpenProcessToken(process, access, token.0 as *mut u32) })
}

/// NtAdjustPrivilegesToken: the token's privileges adjusted as the caller's `new_state` says (or
/// all disabled), what changed reported in its `previous_state` of `length` bytes and its size in
/// `return_length`: the service's status, a success among several (STATUS_NOT_ALL_ASSIGNED).
pub fn adjust_privileges_token(
    token: u32,
    disable_all: bool,
    new_state: Passed,
    length: u32,
    previous_state: Passed,
    return_length: Passed,
) -> NtStatus {
    // SAFETY: the service reads and writes only the caller's memory handed through, which it
    // probes.
    NtStatus(unsafe {
        raw::NtAdjustPrivilegesToken(
            token,
            u8::from(disable_all),
            new_state.0 as *const u8,
            length,
            previous_state.0 as *mut u8,
            return_length.0 as *mut u32,
        )
    })
}

/// NtQueryInformationToken: the token's information of `class` into the caller's `information`
/// of `length` bytes, its size into `return_length`.
pub fn query_information_token(
    token: u32,
    class: u32,
    information: Passed,
    length: u32,
    return_length: Passed,
) -> Result<(), NtStatus> {
    // SAFETY: the service writes only the caller's memory handed through, which it probes.
    checked(unsafe {
        raw::NtQueryInformationToken(
            token,
            class,
            information.0 as *mut u8,
            length,
            return_length.0 as *mut u32,
        )
    })
}

/// SECURITY_QUALITY_OF_SERVICE: its size, the impersonation level, the context tracking (static,
/// 0) and whether only the enabled parts are effective.
#[repr(C)]
struct QualityOfService {
    length: u32,
    level: u32,
    tracking: u8,
    effective_only: u8,
}

/// NtDuplicateToken: a copy of `token` of type `kind` (an impersonation token at `level`, static
/// tracking, not effective only), opened with `access`, its handle written to the caller's
/// `duplicate`.
pub fn duplicate_token(
    token: u32,
    access: u32,
    level: u32,
    kind: u32,
    duplicate: Passed,
) -> Result<(), NtStatus> {
    let quality = QualityOfService {
        length: 12,
        level,
        tracking: 0,
        effective_only: 0,
    };
    let attributes = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: core::ptr::null(),
        attributes: 0,
        security_descriptor: core::ptr::null(),
        security_quality_of_service: (&quality as *const QualityOfService).cast(),
    };
    // SAFETY: the attributes and their quality of service live across the call; the one place
    // the service writes is the caller's, which it probes.
    checked(unsafe {
        raw::NtDuplicateToken(token, access, &attributes, 0, kind, duplicate.0 as *mut u32)
    })
}

/// NtEnumerateKey: subkey `index` of `key`'s information of `class`, into `information`: the
/// bytes the information takes.
pub fn enumerate_key(
    key: u32,
    index: u32,
    class: u32,
    information: &mut [u8],
) -> Result<u32, NtStatus> {
    let answer = enumerate_key_answer(key, index, class, information);
    checked(answer.status.0)?;
    Ok(answer.length)
}

/// A key service's answer into a buffer whatever it is: its status, and the bytes the whole
/// information takes (ResultLength), which an answer too long for the buffer reports too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    pub status: NtStatus,
    pub length: u32,
}

/// NtEnumerateKey: subkey `index` of `key`'s information of `class`, into `information` (see
/// [`Answer`]).
pub fn enumerate_key_answer(key: u32, index: u32, class: u32, information: &mut [u8]) -> Answer {
    let mut length = 0u32;
    // SAFETY: the call writes at most the buffer's length into it, and the length into the local.
    let status = unsafe {
        raw::NtEnumerateKey(
            key,
            index,
            class,
            information.as_mut_ptr(),
            information.len() as u32,
            &mut length,
        )
    };
    Answer {
        status: NtStatus(status),
        length,
    }
}

/// NtEnumerateValueKey: value `index` of `key`'s information of `class`, into `information` (see
/// [`Answer`]).
pub fn enumerate_value_key(key: u32, index: u32, class: u32, information: &mut [u8]) -> Answer {
    let mut length = 0u32;
    // SAFETY: the call writes at most the buffer's length into it, and the length into the local.
    let status = unsafe {
        raw::NtEnumerateValueKey(
            key,
            index,
            class,
            information.as_mut_ptr(),
            information.len() as u32,
            &mut length,
        )
    };
    Answer {
        status: NtStatus(status),
        length,
    }
}

/// NtQueryKey: `key`'s own information of `class`, into `information` (see [`Answer`]).
pub fn query_key(key: u32, class: u32, information: &mut [u8]) -> Answer {
    let mut length = 0u32;
    // SAFETY: the call writes at most the buffer's length into it, and the length into the local.
    let status = unsafe {
        raw::NtQueryKey(
            key,
            class,
            information.as_mut_ptr(),
            information.len() as u32,
            &mut length,
        )
    };
    Answer {
        status: NtStatus(status),
        length,
    }
}

/// NtQueryValueKey: `name`'s value of `key`, its information of `class` into `information`: the
/// bytes the information takes. STATUS_BUFFER_OVERFLOW is a failure that wrote the information's
/// fixed part.
pub fn query_value_key(
    key: u32,
    name: &Counted,
    class: u32,
    information: &mut [u8],
) -> Result<u32, NtStatus> {
    let mut length = 0u32;
    // SAFETY: the name lives across the call; the call writes at most the buffer's length into
    // it, and the length into the local.
    checked(unsafe {
        raw::NtQueryValueKey(
            key,
            &name.string,
            class,
            information.as_mut_ptr(),
            information.len() as u32,
            &mut length,
        )
    })?;
    Ok(length)
}

/// NtSetValueKey: `name`'s value of `key` set to `data`, of type `kind`.
pub fn set_value_key(key: u32, name: &Counted, kind: u32, data: &[u8]) -> Result<(), NtStatus> {
    // SAFETY: the name and the data live across the call, which reads the data's length of it.
    checked(unsafe {
        raw::NtSetValueKey(key, &name.string, 0, kind, data.as_ptr(), data.len() as u32)
    })
}

/// RtlAnsiStringToUnicodeString: `text` (its first 65534 bytes: what a counted string holds)
/// converted into a string of its own.
pub fn ansi_to_unicode(text: &[u8]) -> Result<Wide, NtStatus> {
    let length = text.len().min(0xFFFE) as u16;
    let source = AnsiString {
        length,
        maximum_length: length,
        buffer: text.as_ptr().cast_mut(),
    };
    let mut string = UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: core::ptr::null_mut(),
    };
    // SAFETY: the source holds its length and is only read; the call allocates the destination's
    // buffer.
    checked(unsafe { raw::RtlAnsiStringToUnicodeString(&mut string, &source, 1) })?;
    Ok(Wide { string })
}

/// RtlUnicodeStringToAnsiString: `source` converted into `destination` (its first 65535 bytes):
/// what fits, terminated; STATUS_BUFFER_OVERFLOW when not the whole.
pub fn unicode_to_ansi_string(source: &Counted, destination: &mut [u8]) -> Result<(), NtStatus> {
    let room = destination.len().min(0xFFFF) as u16;
    let mut ansi = AnsiString {
        length: 0,
        maximum_length: room,
        buffer: destination.as_mut_ptr(),
    };
    // SAFETY: the source lives across the call; the call writes at most the destination's room.
    checked(unsafe { raw::RtlUnicodeStringToAnsiString(&mut ansi, &source.string, 0) })
}

/// RtlUnicodeToMultiByteN: as many of `source`'s units as `destination` holds, converted: the bytes
/// written.
pub fn unicode_to_multi_byte(destination: &mut [u8], source: &[u16]) -> usize {
    // SAFETY: the import is the conversion itself (ntdll's, or its stand-in).
    unsafe {
        rtl::string::unicode_to_multi_byte_with(raw::RtlUnicodeToMultiByteN, destination, source)
    }
}

/// RtlMultiByteToUnicodeN: as many of `source`'s bytes as `destination` holds, converted: the units
/// written.
pub fn multi_byte_to_unicode(destination: &mut [u16], source: &[u8]) -> usize {
    // SAFETY: the import is the conversion itself (ntdll's, or its stand-in).
    unsafe {
        rtl::string::multi_byte_to_unicode_with(raw::RtlMultiByteToUnicodeN, destination, source)
    }
}

/// RtlUnicodeToMultiByteSize: the bytes `source` takes in the ANSI code page.
pub fn unicode_to_multi_byte_size(source: &[u16]) -> u32 {
    let mut bytes = 0u32;
    // SAFETY: the call reads the source's units and writes the size into the local.
    unsafe { raw::RtlUnicodeToMultiByteSize(&mut bytes, source.as_ptr(), 2 * source.len() as u32) };
    bytes
}

/// The host tests' imports: stand-ins with the imports' shapes, recording what they were given.
/// The key services have no registry behind them on the host: they answer
/// STATUS_NOT_IMPLEMENTED; the conversions and the heap are real (rtl's shared stand-ins,
/// [`rtl::host`]).
#[cfg(test)]
#[allow(non_snake_case, clippy::missing_safety_doc)]
pub mod host {
    use std::cell::{Cell, RefCell};

    pub use rtl::host::{
        process_heap,
        DbgPrint,
        Probed,
        RaiseException,
        RtlAllocateHeap,
        RtlAnsiStringToUnicodeString,
        RtlFreeHeap,
        RtlFreeUnicodeString,
        RtlMultiByteToUnicodeN,
        RtlNtStatusToDosError,
        RtlUnicodeStringToAnsiString,
        RtlUnicodeToMultiByteN,
        RtlUnicodeToMultiByteSize,
        SetLastError,
        DEBUG_PRINTS,
        LAST_ERROR,
    };
    // What the key services answer on the host.
    use rtl::status::STATUS_NOT_IMPLEMENTED;

    use super::{ObjectAttributes, UnicodeString};

    pub unsafe extern "system" fn NtCreateKey(
        _: *mut u32,
        _: u32,
        _: *const ObjectAttributes,
        _: u32,
        _: *const UnicodeString,
        _: u32,
        _: *mut u32,
    ) -> u32 {
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtOpenKey(
        _: *mut u32,
        _: u32,
        _: *const ObjectAttributes,
    ) -> u32 {
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtDeleteKey(_: u32) -> u32 {
        STATUS_NOT_IMPLEMENTED
    }

    std::thread_local! {
        /// What NtEnumerateKey, NtEnumerateValueKey and NtQueryKey answer on the host: the
        /// information's bytes, delivered as the kernel delivers them (what fits, the whole's size
        /// in ResultLength, STATUS_BUFFER_OVERFLOW when not the whole), or a status
        /// (STATUS_NOT_IMPLEMENTED unless a test sets one); and the information classes asked for.
        pub static KEY_REPLY: RefCell<Result<std::vec::Vec<u8>, u32>> = const { RefCell::new(Err(STATUS_NOT_IMPLEMENTED)) };
        pub static KEY_CLASSES: RefCell<std::vec::Vec<u32>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    /// The reply [`KEY_REPLY`] holds, delivered into `length` bytes at `information`.
    unsafe fn deliver(class: u32, information: *mut u8, length: u32, result: *mut u32) -> u32 {
        KEY_CLASSES.with(|classes| classes.borrow_mut().push(class));
        KEY_REPLY.with(|reply| match &*reply.borrow() {
            Err(status) => *status,
            Ok(bytes) => {
                let fits = bytes.len().min(length as usize);
                // SAFETY: the caller's buffer of `length` bytes and its result length.
                unsafe {
                    information.copy_from_nonoverlapping(bytes.as_ptr(), fits);
                    result.write(bytes.len() as u32);
                }
                if fits < bytes.len() {
                    0x8000_0005
                } else {
                    0
                }
            }
        })
    }

    pub unsafe extern "system" fn NtEnumerateKey(
        _: u32,
        _: u32,
        class: u32,
        information: *mut u8,
        length: u32,
        result: *mut u32,
    ) -> u32 {
        // SAFETY: the caller's buffer and result length.
        unsafe { deliver(class, information, length, result) }
    }

    pub unsafe extern "system" fn NtEnumerateValueKey(
        _: u32,
        _: u32,
        class: u32,
        information: *mut u8,
        length: u32,
        result: *mut u32,
    ) -> u32 {
        // SAFETY: the caller's buffer and result length.
        unsafe { deliver(class, information, length, result) }
    }

    pub unsafe extern "system" fn NtQueryKey(
        _: u32,
        class: u32,
        information: *mut u8,
        length: u32,
        result: *mut u32,
    ) -> u32 {
        // SAFETY: the caller's buffer and result length.
        unsafe { deliver(class, information, length, result) }
    }

    pub unsafe extern "system" fn NtQueryValueKey(
        _: u32,
        _: *const UnicodeString,
        _: u32,
        _: *mut u8,
        _: u32,
        _: *mut u32,
    ) -> u32 {
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtSetValueKey(
        _: u32,
        _: *const UnicodeString,
        _: u32,
        _: u32,
        _: *const u8,
        _: u32,
    ) -> u32 {
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn NtClose(_: u32) -> u32 {
        STATUS_NOT_IMPLEMENTED
    }

    pub unsafe extern "system" fn RtlOpenCurrentUser(_: u32, _: *mut u32) -> u32 {
        STATUS_NOT_IMPLEMENTED
    }

    std::thread_local! {
        /// The status the token services answer (success unless a test sets one), and the
        /// arguments each was last handed: the process or token handle, and the access, the
        /// DisableAllPrivileges flag or the class.
        pub static TOKEN_STATUS: Cell<u32> = const { Cell::new(0) };
        pub static TOKEN_CALLS: RefCell<std::vec::Vec<(&'static str, u32, u32)>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    /// The handle NtOpenProcessToken hands out.
    pub const TOKEN: u32 = 0x58;

    fn token_call(service: &'static str, handle: u32, value: u32) -> u32 {
        TOKEN_CALLS.with(|calls| calls.borrow_mut().push((service, handle, value)));
        TOKEN_STATUS.with(|status| status.get())
    }

    pub unsafe extern "system" fn NtOpenProcessToken(
        process: u32,
        access: u32,
        token: *mut u32,
    ) -> u32 {
        let status = token_call("NtOpenProcessToken", process, access);
        if status == 0 {
            if token.is_null() {
                return 0xC000_0005;
            }
            // SAFETY: the caller's handle slot.
            unsafe { token.write(TOKEN) };
        }
        status
    }

    pub unsafe extern "system" fn NtAdjustPrivilegesToken(
        token: u32,
        disable_all: u8,
        _: *const u8,
        _: u32,
        _: *mut u8,
        _: *mut u32,
    ) -> u32 {
        token_call("NtAdjustPrivilegesToken", token, u32::from(disable_all))
    }

    pub unsafe extern "system" fn NtQueryInformationToken(
        token: u32,
        class: u32,
        _: *mut u8,
        _: u32,
        _: *mut u32,
    ) -> u32 {
        token_call("NtQueryInformationToken", token, class)
    }

    pub unsafe extern "system" fn NtDuplicateToken(
        token: u32,
        access: u32,
        _: *const ObjectAttributes,
        _: u8,
        _: u32,
        duplicate: *mut u32,
    ) -> u32 {
        let status = token_call("NtDuplicateToken", token, access);
        if status == 0 {
            // SAFETY: the caller's handle slot.
            unsafe { duplicate.write(TOKEN + 4) };
        }
        status
    }

    /// GetComputerNameW: the computer's name, QEMU (ERROR_BUFFER_OVERFLOW for a buffer without
    /// room for it and its terminator).
    pub unsafe extern "system" fn GetComputerNameW(buffer: *mut u16, size: *mut u32) -> u32 {
        let name: std::vec::Vec<u16> = "QEMU".encode_utf16().collect();
        // SAFETY: the caller's size and buffer of that many characters.
        unsafe {
            if (*size as usize) <= name.len() {
                *size = name.len() as u32 + 1;
                LAST_ERROR.with(|error| error.set(111));
                return 0;
            }
            buffer.copy_from_nonoverlapping(name.as_ptr(), name.len());
            buffer.add(name.len()).write(0);
            *size = name.len() as u32;
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The conversion fakes take NULL with no length, as a caller may pass it, and convert
    /// nothing.
    #[test]
    fn conversions_take_null_with_no_length() {
        let mut written = 7u32;
        // SAFETY: no buffers, of no length; the count goes into the local.
        unsafe {
            host::RtlMultiByteToUnicodeN(
                core::ptr::null_mut(),
                0,
                &mut written,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(written, 0);
        written = 7;
        // SAFETY: as above.
        unsafe {
            host::RtlUnicodeToMultiByteN(
                core::ptr::null_mut(),
                0,
                &mut written,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(written, 0);
    }
}
