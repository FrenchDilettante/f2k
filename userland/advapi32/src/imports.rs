//! advapi32's seam to the other system DLLs: what its code calls, imported by name as Windows
//! 2000's advapi32 imports it (ntdll and kernel32), and the memory probe its stub routine reads
//! arguments through (its import table holds no memory query). The host tests replace them with
//! stand-ins of the same shape ([`host`]).

/// The counted strings, UNICODE_STRING and ANSI_STRING (`rtl::string`'s, which ntdll
/// converts).
pub use rtl::string::{AnsiString, UnicodeString};

/// An OBJECT_ATTRIBUTES (`rtl::nt`'s): what names a key to the key services, its name and security
/// pointers the process's own.
pub type ObjectAttributes = rtl::nt::ObjectAttributes<u32, *const UnicodeString, *const u8>;

#[cfg(all(target_arch = "x86", not(test)))]
#[link(
    name = "kernel32",
    kind = "raw-dylib",
    import_name_type = "undecorated"
)]
unsafe extern "system" {
    /// SetLastError: the calling thread's last error.
    pub fn SetLastError(code: u32);
    /// RaiseException: an exception raised with the code, flags and arguments (a noncontinuable
    /// one does not return).
    pub fn RaiseException(code: u32, flags: u32, count: u32, arguments: *const usize);
}

#[cfg(all(target_arch = "x86", not(test)))]
#[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
unsafe extern "C" {
    /// DbgPrint: the text the format makes, to the debugger (F2K: COM1, as `F2K: debug:` lines).
    pub fn DbgPrint(format: *const u8, ...) -> u32;
}

#[cfg(all(target_arch = "x86", not(test)))]
#[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
unsafe extern "system" {
    /// NtCreateKey: the key the attributes name, made when its last name is missing; its handle,
    /// and whether it was made (REG_CREATED_NEW_KEY) or opened (REG_OPENED_EXISTING_KEY).
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
    /// RtlAnsiStringToUnicodeString: the ANSI string converted (into a process-heap buffer when
    /// asked to allocate it, which RtlFreeUnicodeString frees).
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
    /// RtlUnicodeToMultiByteN, RtlMultiByteToUnicodeN and RtlUnicodeToMultiByteSize: the ANSI code
    /// page's conversions of counted buffers.
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
#[cfg(all(target_arch = "x86", not(test)))]
pub fn process_heap() -> usize {
    rtl::sys::process_heap_handle()
}

#[cfg(test)]
pub use host::*;
/// The caller's memory as the stub routine reads it: probed byte by byte.
#[cfg(all(target_arch = "x86", not(test)))]
pub use rtl::probe::Probed;

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
    pub unsafe extern "C" fn DbgPrint(format: *const u8, text: *const u8) -> u32 {
        // SAFETY: the caller's NUL-terminated format and text.
        let (format, text) = unsafe {
            (
                core::ffi::CStr::from_ptr(format.cast()).to_bytes(),
                core::ffi::CStr::from_ptr(text.cast()),
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

    /// The host heap's blocks, by address, with their layouts.
    fn heap_alloc(size: usize) -> *mut u8 {
        let layout = std::alloc::Layout::from_size_align(size.max(1) + 8, 8).unwrap();
        // SAFETY: a nonzero size; the block's first 8 bytes keep its size for the free.
        unsafe {
            let block = std::alloc::alloc(layout);
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
