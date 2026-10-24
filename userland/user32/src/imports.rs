//! user32's seam to the rest of the system: what its code calls, imported by name as Windows 2000's
//! user32 imports it (ntdll and kernel32), win32k's services through user32's own stubs (as
//! Windows 2000's user32 enters the kernel itself), the process heap through the PEB, and the
//! memory probe its stub routine reads arguments through (its import table holds no memory query).
//! The host tests replace them with stand-ins of the same shape ([`host`]).
//!
//! One import is not Windows 2000's: ntdll's DbgPrint, which the stub routine logs through
//! (`scripts/compat.py` tolerates exactly that one, for the stubs' log line).

#[cfg(all(target_arch = "x86", not(test)))]
#[link(
    name = "kernel32",
    kind = "raw-dylib",
    import_name_type = "undecorated"
)]
unsafe extern "system" {
    /// SetLastError: the calling thread's last error.
    pub fn SetLastError(code: u32);
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
    /// RtlNtStatusToDosError: the Win32 error a failed service's status maps to.
    pub fn RtlNtStatusToDosError(status: u32) -> u32;
    /// RtlAllocateHeap and RtlFreeHeap: a block of the heap, and its release.
    pub fn RtlAllocateHeap(heap: usize, flags: u32, size: usize) -> *mut u8;
    pub fn RtlFreeHeap(heap: usize, flags: u32, block: *mut u8) -> u32;
    /// RtlUnicodeToMultiByteN: UTF-16 to the ANSI code page, what fits.
    pub fn RtlUnicodeToMultiByteN(
        multi_byte: *mut u8,
        max_bytes: u32,
        bytes_written: *mut u32,
        unicode: *const u16,
        unicode_bytes: u32,
    ) -> u32;
}

// win32k's services: user32's own stubs (generated from its spec's internal syscall records), each
// raising the gate on its Windows 2000 number. Their symbols are the stubs' labels, undecorated:
// the leading \u{1} keeps the compiler from adding stdcall's `@<bytes>`.
#[cfg(all(target_arch = "x86", not(test)))]
core::arch::global_asm!(
    include_str!(concat!(env!("OUT_DIR"), "/consts.s")),
    include_str!(concat!(env!("OUT_DIR"), "/stubs.s")),
);

#[cfg(all(target_arch = "x86", not(test)))]
unsafe extern "system" {
    /// NtUserGetProcessWindowStation: the process's window station handle, into `window_station`.
    #[link_name = "\u{1}_f2k_nt_NtUserGetProcessWindowStation"]
    pub fn NtUserGetProcessWindowStation(window_station: *mut u32) -> u32;
    /// NtUserGetThreadDesktop: the desktop handle of thread `thread_id`, into `desktop`.
    #[link_name = "\u{1}_f2k_nt_NtUserGetThreadDesktop"]
    pub fn NtUserGetThreadDesktop(thread_id: u32, desktop: *mut u32) -> u32;
    /// NtUserGetObjectInformation: GetUserObjectInformationW's answer: into `information` when
    /// `length` holds it, its length into `needed` in every case.
    #[link_name = "\u{1}_f2k_nt_NtUserGetObjectInformation"]
    pub fn NtUserGetObjectInformation(
        object: usize,
        index: u32,
        information: *mut u8,
        length: u32,
        needed: *mut u32,
    ) -> u32;
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
#[cfg(test)]
#[allow(non_snake_case)]
pub mod host {
    use std::cell::{Cell, RefCell};

    std::thread_local! {
        /// The calling thread's last error, as SetLastError left it.
        pub static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
        /// The text each DbgPrint printed, in order.
        pub static DEBUG_PRINTS: RefCell<std::vec::Vec<std::string::String>> = const { RefCell::new(std::vec::Vec::new()) };
        /// The window station handle, the desktop handle and the thread the services know, as the
        /// kernel answers them.
        pub static WINDOW_STATION: Cell<u32> = const { Cell::new(0x18) };
        pub static DESKTOP: Cell<u32> = const { Cell::new(0x1C) };
        pub static THREAD_ID: Cell<u32> = const { Cell::new(0x10) };
        /// How many win32k services were called.
        pub static SERVICES: Cell<u32> = const { Cell::new(0) };
    }

    pub unsafe extern "system" fn SetLastError(code: u32) {
        LAST_ERROR.with(|error| error.set(code));
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

    pub unsafe extern "system" fn RtlNtStatusToDosError(status: u32) -> u32 {
        rtl::status::dos_error(status)
    }

    /// The heap: the host's allocator, a block's size kept before it.
    pub unsafe extern "system" fn RtlAllocateHeap(
        _heap: usize,
        _flags: u32,
        size: usize,
    ) -> *mut u8 {
        let layout = std::alloc::Layout::from_size_align(size + 8, 8).unwrap();
        // SAFETY: a non-zero layout; the size goes in the first word.
        unsafe {
            let block = std::alloc::alloc(layout);
            (block as *mut usize).write(size);
            block.add(8)
        }
    }

    pub unsafe extern "system" fn RtlFreeHeap(_heap: usize, _flags: u32, block: *mut u8) -> u32 {
        // SAFETY: a block RtlAllocateHeap made.
        unsafe {
            let start = block.sub(8);
            let size = (start as *const usize).read();
            std::alloc::dealloc(
                start,
                std::alloc::Layout::from_size_align(size + 8, 8).unwrap(),
            );
        }
        1
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
                core::slice::from_raw_parts_mut(multi_byte, max_bytes as usize),
                core::slice::from_raw_parts(unicode, unicode_bytes as usize / 2),
            )
        };
        if !bytes_written.is_null() {
            // SAFETY: the caller's count.
            unsafe { bytes_written.write(written as u32) };
        }
        0
    }

    pub unsafe extern "system" fn NtUserGetProcessWindowStation(window_station: *mut u32) -> u32 {
        SERVICES.with(|count| count.set(count.get() + 1));
        // SAFETY: the caller's out-pointer.
        unsafe { window_station.write(WINDOW_STATION.with(Cell::get)) };
        0
    }

    pub unsafe extern "system" fn NtUserGetThreadDesktop(thread_id: u32, desktop: *mut u32) -> u32 {
        SERVICES.with(|count| count.set(count.get() + 1));
        if thread_id != THREAD_ID.with(Cell::get) {
            return 0xC000_000D;
        }
        // SAFETY: the caller's out-pointer.
        unsafe { desktop.write(DESKTOP.with(Cell::get)) };
        0
    }

    /// The kernel's answers for the stand-ins' window station: its name, its type's name and its
    /// flags (WSF_VISIBLE), with the kernel's lengths and statuses.
    pub unsafe extern "system" fn NtUserGetObjectInformation(
        object: usize,
        index: u32,
        information: *mut u8,
        length: u32,
        needed: *mut u32,
    ) -> u32 {
        SERVICES.with(|count| count.set(count.get() + 1));
        let answer: std::vec::Vec<u8> = match index {
            _ if object != WINDOW_STATION.with(Cell::get) as usize => {
                // SAFETY: the caller's out-pointer.
                unsafe { needed.write(u32::MAX) };
                return 0xC000_0008;
            }
            1 => [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0].to_vec(),
            2 | 3 => {
                let text = if index == 2 {
                    "WinSta0"
                } else {
                    "WindowStation"
                };
                text.encode_utf16()
                    .chain([0])
                    .flat_map(u16::to_le_bytes)
                    .collect()
            }
            _ => {
                // SAFETY: the caller's out-pointer.
                unsafe { needed.write(0) };
                return 0xC000_000D;
            }
        };
        // SAFETY: the caller's out-pointer and buffer, of the length given.
        unsafe {
            needed.write(answer.len() as u32);
            if (length as usize) < answer.len() {
                return 0xC000_0023;
            }
            core::ptr::copy_nonoverlapping(answer.as_ptr(), information, answer.len());
        }
        0
    }

    pub fn process_heap() -> usize {
        0x0014_0000
    }

    /// The host process's memory: every address the tests hand over is their own.
    pub struct Probed;

    impl rtl::stub::Memory for Probed {
        fn readable(&self, _address: usize) -> bool {
            true
        }
    }
}
