//! user32's seam to the rest of the system: what its code calls, imported by name as Windows 2000's
//! user32 imports it (ntdll and kernel32), win32k's services through user32's own stubs (as
//! Windows 2000's user32 enters the kernel itself), the process heap through the PEB, and the
//! memory probe its stub routine reads arguments through (its import table holds no memory query).
//! The host tests replace the imports with stand-ins of the same shape ([`host`]).
//!
//! Each import is wrapped once here in a safe function over references and slices, a service's
//! failure an `Err` of its status; the only `unsafe` the rest of the DLL's code reaches for an
//! import is here. Memory a service writes for the caller is a [`UserBuffer`], handed to the
//! kernel unread.
//!
//! One import is not Windows 2000's: ntdll's DbgPrint, which the stub routine logs through
//! (`scripts/compat.py` tolerates exactly that one, for the stubs' log line).

use core::ffi::CStr;
use core::marker::PhantomData;
use core::ptr::NonNull;

use rtl::heap::HEAP_ZERO_MEMORY;
use rtl::status::NtStatus;

use crate::Out;

#[cfg(all(target_arch = "x86", not(test)))]
mod raw {
    #[link(
        name = "kernel32",
        kind = "raw-dylib",
        import_name_type = "undecorated"
    )]
    unsafe extern "system" {
        /// SetLastError: the calling thread's last error.
        pub fn SetLastError(code: u32);
    }

    #[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "C" {
        /// DbgPrint: the text the format makes, to the debugger (F2K: COM1, as `F2K: debug:`
        /// lines).
        pub fn DbgPrint(format: *const u8, ...) -> u32;
    }

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

    // win32k's services: user32's own stubs (generated from its spec's internal syscall records),
    // each raising the gate on its Windows 2000 number. Their symbols are the stubs' labels,
    // undecorated: the leading \u{1} keeps the compiler from adding stdcall's `@<bytes>`.
    core::arch::global_asm!(
        include_str!(concat!(env!("OUT_DIR"), "/consts.s")),
        include_str!(concat!(env!("OUT_DIR"), "/stubs.s")),
    );

    unsafe extern "system" {
        /// NtUserGetProcessWindowStation: the process's window station handle, into
        /// `window_station`.
        #[link_name = "\u{1}_f2k_nt_NtUserGetProcessWindowStation"]
        pub fn NtUserGetProcessWindowStation(window_station: *mut u32) -> u32;
        /// NtUserGetThreadDesktop: the desktop handle of thread `thread_id`, into `desktop`.
        #[link_name = "\u{1}_f2k_nt_NtUserGetThreadDesktop"]
        pub fn NtUserGetThreadDesktop(thread_id: u32, desktop: *mut u32) -> u32;
        /// NtUserGetObjectInformation: GetUserObjectInformationW's answer: into `information`
        /// when `length` holds it, its length into `needed` in every case.
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

/// A service's answer: success for a status of success, information or warning severity, an
/// error's status its failure.
fn checked(status: u32) -> Result<(), NtStatus> {
    if (status as i32) < 0 {
        Err(NtStatus(status))
    } else {
        Ok(())
    }
}

/// A caller's buffer handed to a win32k service unread: its address and length, which the kernel
/// probes and writes through its fault-tolerant copies (a bad address fails the service). Nothing
/// in this DLL reads or writes it.
pub struct UserBuffer<'a> {
    at: *mut u8,
    length: u32,
    memory: PhantomData<&'a mut [u8]>,
}

impl<'a> UserBuffer<'a> {
    /// The caller's `length` bytes at `at`, as given (null or not, reachable or not).
    ///
    /// # Safety
    ///
    /// `at` is the caller's memory, or an address the kernel refuses: never memory this DLL holds
    /// a reference into, which the service would write behind it.
    pub unsafe fn new(at: *mut u8, length: u32) -> Self {
        UserBuffer {
            at,
            length,
            memory: PhantomData,
        }
    }

    /// No buffer: a null address and no length.
    pub fn none() -> Self {
        UserBuffer {
            at: core::ptr::null_mut(),
            length: 0,
            memory: PhantomData,
        }
    }

    /// The buffer's address, as given.
    pub fn address(&self) -> usize {
        self.at as usize
    }

    /// The buffer's length, as given.
    pub fn length(&self) -> u32 {
        self.length
    }
}

impl<'a> From<&'a mut [u8]> for UserBuffer<'a> {
    /// A buffer of this DLL's own, lent to the service.
    fn from(bytes: &'a mut [u8]) -> Self {
        UserBuffer {
            at: bytes.as_mut_ptr(),
            length: bytes.len() as u32,
            memory: PhantomData,
        }
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

    /// The block's bytes, to write.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: the block holds `size` initialized (zeroed) bytes, ours alone while it lives.
        unsafe { core::slice::from_raw_parts_mut(self.at.as_ptr(), self.size) }
    }

    /// The block's bytes as UTF-16 units (an odd last byte left out).
    pub fn units(&self) -> &[u16] {
        // SAFETY: the heap's blocks are 8-aligned (its granularity); the block holds `size`
        // initialized bytes, any of which make a unit.
        unsafe { core::slice::from_raw_parts(self.at.as_ptr().cast(), self.size / 2) }
    }
}

impl Drop for HeapBlock {
    fn drop(&mut self) {
        // SAFETY: our own block, freed once.
        unsafe { raw::RtlFreeHeap(raw::process_heap(), 0, self.at.as_ptr()) };
    }
}

// --- kernel32
// ----------------------------------------------------------------------------------------

/// SetLastError: the calling thread's last error.
pub fn set_last_error(code: u32) {
    // SAFETY: no pointers; it writes the thread's own TEB.
    unsafe { raw::SetLastError(code) }
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

// --- win32k
// ------------------------------------------------------------------------------------------

/// NtUserGetProcessWindowStation: the process's window station handle.
pub fn process_window_station() -> Result<u32, NtStatus> {
    let mut handle = 0u32;
    // SAFETY: the service writes the handle into the local.
    checked(unsafe { raw::NtUserGetProcessWindowStation(&mut handle) })?;
    Ok(handle)
}

/// NtUserGetThreadDesktop: the desktop handle of the process's thread `thread_id`.
pub fn thread_desktop(thread_id: u32) -> Result<u32, NtStatus> {
    let mut handle = 0u32;
    // SAFETY: the service writes the handle into the local.
    checked(unsafe { raw::NtUserGetThreadDesktop(thread_id, &mut handle) })?;
    Ok(handle)
}

/// NtUserGetObjectInformation: `object`'s information `index` into `information` when it holds
/// it, the length the information takes into `needed` in every case (a null address for none:
/// the kernel refuses it).
pub fn object_information(
    object: usize,
    index: u32,
    information: UserBuffer,
    needed: Option<&mut Out<'_, u32>>,
) -> Result<(), NtStatus> {
    let needed = needed.map_or(core::ptr::null_mut(), |needed| needed.as_ptr());
    // SAFETY: the kernel probes the buffer and the length's place, and writes them through its
    // fault-tolerant copies; neither is memory this DLL holds a reference into.
    checked(unsafe {
        raw::NtUserGetObjectInformation(object, index, information.at, information.length, needed)
    })
}

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
    pub unsafe extern "C" fn DbgPrint(format: *const u8, text: *const core::ffi::c_char) -> u32 {
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

    /// The heap: the host's allocator, a block zeroed, its size kept before it.
    pub unsafe extern "system" fn RtlAllocateHeap(
        _heap: usize,
        _flags: u32,
        size: usize,
    ) -> *mut u8 {
        let layout = std::alloc::Layout::from_size_align(size + 8, 8).unwrap();
        // SAFETY: a non-zero layout; the size goes in the first word.
        unsafe {
            let block = std::alloc::alloc_zeroed(layout);
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
