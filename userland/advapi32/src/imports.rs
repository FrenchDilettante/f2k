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
//! key).

use core::ffi::CStr;
use core::marker::PhantomData;
use core::ptr::NonNull;

use rtl::heap::HEAP_ZERO_MEMORY;
use rtl::status::{NtStatus, STATUS_SUCCESS};
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

/// A service's answer: success for STATUS_SUCCESS alone, any other status its failure.
fn checked(status: u32) -> Result<(), NtStatus> {
    if status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(NtStatus(status))
    }
}

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

/// A zeroed block of the process heap, freed when dropped.
pub struct HeapBlock {
    at: NonNull<u8>,
    size: usize,
}

impl HeapBlock {
    /// `size` bytes, zeroed: none when the heap has no room.
    pub fn new(size: usize) -> Option<HeapBlock> {
        // SAFETY: a plain allocation of at least a byte.
        let at =
            unsafe { raw::RtlAllocateHeap(raw::process_heap(), HEAP_ZERO_MEMORY, size.max(1)) };
        NonNull::new(at).map(|at| HeapBlock { at, size })
    }

    /// The block's bytes.
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the block holds `size` initialized (zeroed) bytes, ours alone while it lives.
        unsafe { core::slice::from_raw_parts(self.at.as_ptr(), self.size) }
    }

    /// The block's bytes, to write.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as in `bytes`, borrowed mutably through the block.
        unsafe { core::slice::from_raw_parts_mut(self.at.as_ptr(), self.size) }
    }

    /// The block's bytes as UTF-16 units (an odd last byte left out).
    pub fn units(&self) -> &[u16] {
        // SAFETY: the heap's blocks are 8-aligned (its granularity); the block holds `size`
        // initialized bytes, any of which make a unit.
        unsafe { core::slice::from_raw_parts(self.at.as_ptr().cast(), self.size / 2) }
    }

    /// The block's bytes as UTF-16 units, to write.
    pub fn units_mut(&mut self) -> &mut [u16] {
        // SAFETY: as in `units`, borrowed mutably through the block.
        unsafe { core::slice::from_raw_parts_mut(self.at.as_ptr().cast(), self.size / 2) }
    }
}

impl Drop for HeapBlock {
    fn drop(&mut self) {
        // SAFETY: our own block, freed once.
        unsafe { raw::RtlFreeHeap(raw::process_heap(), 0, self.at.as_ptr()) };
    }
}

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

// --- ntdll -------------------------------------------------------------------------------------------

/// DbgPrint of `text`, as is (through `"%s"`).
pub fn debug_print(text: &CStr) {
    // SAFETY: the format and the text are NUL-terminated; the format takes the one string.
    unsafe { raw::DbgPrint(c"%s".as_ptr().cast(), text.as_ptr()) };
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

/// NtEnumerateKey: subkey `index` of `key`'s information of `class`, into `information`: the
/// bytes the information takes.
pub fn enumerate_key(
    key: u32,
    index: u32,
    class: u32,
    information: &mut [u8],
) -> Result<u32, NtStatus> {
    let mut length = 0u32;
    // SAFETY: the call writes at most the buffer's length into it, and the length into the local.
    checked(unsafe {
        raw::NtEnumerateKey(
            key,
            index,
            class,
            information.as_mut_ptr(),
            information.len() as u32,
            &mut length,
        )
    })?;
    Ok(length)
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
    let mut written = 0u32;
    // SAFETY: the call reads the source's units and writes at most the destination's bytes, and
    // the count into the local.
    unsafe {
        raw::RtlUnicodeToMultiByteN(
            destination.as_mut_ptr(),
            destination.len() as u32,
            &mut written,
            source.as_ptr(),
            2 * source.len() as u32,
        )
    };
    written as usize
}

/// RtlMultiByteToUnicodeN: as many of `source`'s bytes as `destination` holds, converted: the units
/// written.
pub fn multi_byte_to_unicode(destination: &mut [u16], source: &[u8]) -> usize {
    let mut written = 0u32;
    // SAFETY: the call reads the source's bytes and writes at most the destination's units, and
    // the count of bytes into the local.
    unsafe {
        raw::RtlMultiByteToUnicodeN(
            destination.as_mut_ptr(),
            2 * destination.len() as u32,
            &mut written,
            source.as_ptr(),
            source.len() as u32,
        )
    };
    written as usize / 2
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
/// STATUS_NOT_IMPLEMENTED; the conversions and the heap are real.
#[cfg(test)]
#[allow(non_snake_case, clippy::missing_safety_doc)]
pub mod host {
    use std::cell::{Cell, RefCell};

    use super::{AnsiString, ObjectAttributes, UnicodeString};

    /// What the key services answer on the host.
    const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

    std::thread_local! {
        /// The calling thread's last error, as SetLastError left it.
        pub static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
        /// The text each DbgPrint printed, in order.
        pub static DEBUG_PRINTS: RefCell<std::vec::Vec<std::string::String>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    pub unsafe extern "system" fn SetLastError(code: u32) {
        LAST_ERROR.with(|error| error.set(code));
    }

    pub unsafe extern "system" fn RaiseException(
        code: u32,
        flags: u32,
        _count: u32,
        _arguments: *const usize,
    ) {
        panic!("RaiseException({code:#010x}, {flags:#x})")
    }

    /// DbgPrint, as the stub routine calls it: `"%s"` and the text (the stand-in serves that
    /// format alone), kept.
    pub unsafe extern "C" fn DbgPrint(format: *const u8, text: *const core::ffi::c_char) -> u32 {
        // SAFETY: the caller's NUL-terminated format and text.
        let (format, text) = unsafe {
            (
                core::ffi::CStr::from_ptr(format.cast()).to_bytes(),
                core::ffi::CStr::from_ptr(text),
            )
        };
        assert_eq!(format, b"%s", "the stand-in serves \"%s\" alone");
        DEBUG_PRINTS.with(|prints| {
            prints
                .borrow_mut()
                .push(text.to_string_lossy().into_owned())
        });
        0
    }

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

    pub unsafe extern "system" fn NtEnumerateKey(
        _: u32,
        _: u32,
        _: u32,
        _: *mut u8,
        _: u32,
        _: *mut u32,
    ) -> u32 {
        STATUS_NOT_IMPLEMENTED
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

    pub unsafe extern "system" fn RtlNtStatusToDosError(status: u32) -> u32 {
        rtl::status::dos_error(status)
    }

    /// The host heap's blocks, zeroed, by address, with their layouts.
    fn heap_alloc(size: usize) -> *mut u8 {
        let layout = std::alloc::Layout::from_size_align(size.max(1) + 8, 8).unwrap();
        // SAFETY: a nonzero size; the block's first 8 bytes keep its size for the free.
        unsafe {
            let block = std::alloc::alloc_zeroed(layout);
            (block as *mut usize).write(size.max(1) + 8);
            block.add(8)
        }
    }

    fn heap_free(block: *mut u8) {
        // SAFETY: a block heap_alloc made, its size 8 bytes before it.
        unsafe {
            let base = block.sub(8);
            let size = (base as *const usize).read();
            std::alloc::dealloc(base, std::alloc::Layout::from_size_align(size, 8).unwrap());
        }
    }

    pub unsafe extern "system" fn RtlAnsiStringToUnicodeString(
        destination: *mut UnicodeString,
        source: *const AnsiString,
        allocate: u32,
    ) -> u32 {
        // SAFETY: the caller's strings.
        unsafe {
            rtl::string::ansi_string_to_unicode_string(
                &mut *destination,
                &*source,
                allocate != 0,
                heap_alloc,
            )
        }
    }

    pub unsafe extern "system" fn RtlUnicodeStringToAnsiString(
        destination: *mut AnsiString,
        source: *const UnicodeString,
        allocate: u32,
    ) -> u32 {
        // SAFETY: the caller's strings.
        unsafe {
            rtl::string::unicode_string_to_ansi_string(
                &mut *destination,
                &*source,
                allocate != 0,
                heap_alloc,
            )
        }
    }

    pub unsafe extern "system" fn RtlFreeUnicodeString(string: *mut UnicodeString) {
        // SAFETY: the caller's string.
        rtl::string::free_unicode_string(unsafe { &mut *string }, heap_free);
    }

    pub unsafe extern "system" fn RtlUnicodeToMultiByteN(
        multi_byte: *mut u8,
        max_bytes: u32,
        bytes_written: *mut u32,
        unicode: *const u16,
        unicode_bytes: u32,
    ) -> u32 {
        // SAFETY: the caller's buffers, of the sizes given.
        let written = unsafe {
            rtl::string::unicode_to_multi_byte(
                std::slice::from_raw_parts_mut(multi_byte, max_bytes as usize),
                std::slice::from_raw_parts(unicode, unicode_bytes as usize / 2),
            )
        };
        if !bytes_written.is_null() {
            // SAFETY: the caller's count.
            unsafe { bytes_written.write(written as u32) };
        }
        0
    }

    pub unsafe extern "system" fn RtlMultiByteToUnicodeN(
        unicode: *mut u16,
        max_bytes: u32,
        bytes_written: *mut u32,
        multi_byte: *const u8,
        multi_byte_bytes: u32,
    ) -> u32 {
        // SAFETY: the caller's buffers, of the sizes given.
        let written = unsafe {
            rtl::string::multi_byte_to_unicode(
                std::slice::from_raw_parts_mut(unicode, max_bytes as usize / 2),
                std::slice::from_raw_parts(multi_byte, multi_byte_bytes as usize),
            )
        };
        if !bytes_written.is_null() {
            // SAFETY: the caller's count.
            unsafe { bytes_written.write(2 * written as u32) };
        }
        0
    }

    pub unsafe extern "system" fn RtlUnicodeToMultiByteSize(
        bytes: *mut u32,
        _: *const u16,
        unicode_bytes: u32,
    ) -> u32 {
        // SAFETY: the caller's count.
        unsafe { bytes.write(rtl::string::unicode_to_multi_byte_size(unicode_bytes)) };
        0
    }

    pub unsafe extern "system" fn RtlAllocateHeap(_: usize, _: u32, size: usize) -> *mut u8 {
        heap_alloc(size)
    }

    pub unsafe extern "system" fn RtlFreeHeap(_: usize, _: u32, block: *mut u8) -> u32 {
        heap_free(block);
        1
    }

    /// The host process has no PEB: the stand-in heap is the one heap.
    pub fn process_heap() -> usize {
        0
    }

    /// The host process's memory: every address the tests hand over is their own.
    pub struct Probed;

    impl rtl::stub::Memory for Probed {
        fn readable(&self, _address: usize) -> bool {
            true
        }
    }
}
