//! kernel32's seam to ntdll: the system services and runtime-library functions its code calls,
//! imported from ntdll.dll by name as Windows 2000's kernel32 imports them (kernel32's only import
//! is ntdll). The host tests replace the imports with stand-ins of the same shape ([`host`]), over
//! a process laid out as the kernel lays one out ([`threads`]).
//!
//! An import is declared in the raw-dylib block below; its stand-in, of the same signature, in
//! [`host`]. A stand-in records what it was given in thread-locals and fails on demand
//! ([`host::FAIL_NEXT`]).

/// A UNICODE_STRING: its length and room in bytes, and its buffer.
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

/// An OBJECT_ATTRIBUTES: what names an object to the system services.
#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: u32,
    pub object_name: *const UnicodeString,
    pub attributes: u32,
    pub security_descriptor: *const u8,
    pub security_quality_of_service: *const u8,
}

/// A CSR_API_MSG, Windows 2000's: the LPC header, the capture buffer, the API number, the server's
/// answer, then the API's data (see `rtl::console`: F2K's console server's dwords, pointer-sized so
/// the host tests' buffers are host addresses).
#[repr(C)]
pub struct ApiMessage {
    pub port_message: [u32; 6],
    pub capture_buffer: usize,
    pub api_number: u32,
    pub return_value: u32,
    pub reserved: u32,
    pub data: [usize; rtl::console::DATA_WORDS],
}

#[cfg(target_arch = "x86")]
const _: () = {
    use rtl::console::header;
    assert!(core::mem::offset_of!(ApiMessage, capture_buffer) == header::CAPTURE_BUFFER);
    assert!(core::mem::offset_of!(ApiMessage, api_number) == header::API_NUMBER);
    assert!(core::mem::offset_of!(ApiMessage, return_value) == header::RETURN_VALUE);
    assert!(core::mem::offset_of!(ApiMessage, reserved) == header::RESERVED);
    assert!(core::mem::offset_of!(ApiMessage, data) == header::DATA);
    assert!(core::mem::size_of::<ApiMessage>() == rtl::console::MESSAGE_BYTES);
};

#[cfg(all(target_arch = "x86", not(test)))]
#[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
unsafe extern "system" {
    /// NtClose: the handle released (STATUS_INVALID_HANDLE for one naming nothing).
    pub fn NtClose(handle: u32) -> u32;
    /// NtTerminateProcess: the process the handle names ended with the status (the calling one
    /// only: it does not return then).
    pub fn NtTerminateProcess(process: u32, status: u32) -> u32;
    /// The console server's call (the message's ReturnValue).
    pub fn CsrClientCallServer(
        message: *mut ApiMessage,
        capture_buffer: *mut u8,
        api: u32,
        length: u32,
    ) -> u32;
    /// RtlNtStatusToDosError: the Win32 error a status maps to (the status kept as the thread's
    /// last status).
    pub fn RtlNtStatusToDosError(status: u32) -> u32;
    /// NtQuerySystemInformation: the class's structure into the caller's buffer (F2K answers the
    /// basic, processor and performance information and the time zone: classes 0, 1, 2 and 44).
    pub fn NtQuerySystemInformation(
        class: u32,
        information: *mut u8,
        length: u32,
        return_length: *mut u32,
    ) -> u32;
    /// NtQueryPerformanceCounter: the counter and, when asked, its frequency.
    pub fn NtQueryPerformanceCounter(counter: *mut u64, frequency: *mut u64) -> u32;
    /// NtQueryInformationProcess: the class's structure (F2K answers the VM counters, class 3).
    pub fn NtQueryInformationProcess(
        process: u32,
        class: u32,
        information: *mut u8,
        length: u32,
        returned: *mut u32,
    ) -> u32;
    /// The virtual-memory services, over the process's address space (the in/out base and size
    /// settled on written back).
    pub fn NtAllocateVirtualMemory(
        process: u32,
        base: *mut usize,
        zero_bits: u32,
        size: *mut usize,
        kind: u32,
        protect: u32,
    ) -> u32;
    pub fn NtFreeVirtualMemory(process: u32, base: *mut usize, size: *mut usize, kind: u32) -> u32;
    pub fn NtProtectVirtualMemory(
        process: u32,
        base: *mut usize,
        size: *mut usize,
        protect: u32,
        old: *mut u32,
    ) -> u32;
    pub fn NtQueryVirtualMemory(
        process: u32,
        address: usize,
        class: u32,
        information: *mut u8,
        length: usize,
        returned: *mut usize,
    ) -> u32;
    /// The section services: a section made or opened by name, a view of it mapped and unmapped.
    pub fn NtCreateSection(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        maximum: *const i64,
        protect: u32,
        allocation: u32,
        file: u32,
    ) -> u32;
    pub fn NtOpenSection(handle: *mut u32, access: u32, attributes: *const ObjectAttributes) -> u32;
    pub fn NtMapViewOfSection(
        section: u32,
        process: u32,
        base: *mut usize,
        zero_bits: u32,
        commit_size: usize,
        offset: *mut i64,
        size: *mut usize,
        inherit: u32,
        allocation: u32,
        protect: u32,
    ) -> u32;
    pub fn NtUnmapViewOfSection(process: u32, base: usize) -> u32;
    /// RtlRaiseException: the record raised from the caller (its context captured; a continued
    /// exception returns).
    pub fn RtlRaiseException(record: *mut rtl::seh::ExceptionRecord);
    /// RtlUnwind: the thread's exception chain unwound to the target frame, then a return to the
    /// caller.
    pub fn RtlUnwind(
        target_frame: u32,
        target_ip: u32,
        record: *mut rtl::seh::ExceptionRecord,
        return_value: u32,
    );
}

#[cfg(test)]
pub use host::*;

/// The host tests' ntdll: stand-ins with the imports' shapes.
#[cfg(test)]
#[allow(non_snake_case)]
pub mod host {
    use std::cell::{Cell, RefCell};

    std::thread_local! {
        /// The status the next system service a test stands in for fails with (0: it succeeds).
        pub static FAIL_NEXT: Cell<u32> = const { Cell::new(0) };
        /// The handles NtClose was given, in order.
        pub static CLOSED: RefCell<std::vec::Vec<u32>> = const { RefCell::new(std::vec::Vec::new()) };
        /// The NtTerminateProcess calls: the handle and the status.
        pub static TERMINATED: RefCell<std::vec::Vec<(u32, u32)>> = const { RefCell::new(std::vec::Vec::new()) };
        /// The console server's handles for the test's process (a fresh process's to start).
        pub static CONSOLE_HANDLES: Cell<rtl::console::Handles> = const { Cell::new(rtl::console::Handles::standard()) };
        /// The bytes each console write showed, with its handle.
        pub static CONSOLE: RefCell<std::vec::Vec<(u32, std::vec::Vec<u8>)>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    /// The status the next service answers with: the one FAIL_NEXT holds (reset), or success.
    fn answer() -> u32 {
        FAIL_NEXT.with(|fail| fail.replace(0))
    }

    /// STATUS_INVALID_HANDLE: the kernel's answer for a process handle naming another process.
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    /// NtCurrentProcess.
    const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;

    pub unsafe extern "system" fn NtClose(handle: u32) -> u32 {
        CLOSED.with(|closed| closed.borrow_mut().push(handle));
        answer()
    }

    /// NtTerminateProcess: recorded; only the current process is reachable (the kernel's rule), and
    /// the stand-in returns where the kernel would not.
    pub unsafe extern "system" fn NtTerminateProcess(process: u32, status: u32) -> u32 {
        TERMINATED.with(|terminated| terminated.borrow_mut().push((process, status)));
        if process == CURRENT_PROCESS {
            0
        } else {
            STATUS_INVALID_HANDLE
        }
    }

    pub unsafe extern "system" fn RtlNtStatusToDosError(status: u32) -> u32 {
        rtl::status::dos_error(status)
    }

    std::thread_local! {
        /// The records RtlRaiseException was handed, in order.
        pub static RAISED: RefCell<std::vec::Vec<rtl::seh::ExceptionRecord>> = const { RefCell::new(std::vec::Vec::new()) };
        /// RtlUnwind's calls: the target frame and the record.
        pub static UNWOUND: RefCell<std::vec::Vec<(u32, rtl::seh::ExceptionRecord)>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    /// RtlRaiseException: the record kept (no handler: the raise returns, as a continued one does).
    pub unsafe extern "system" fn RtlRaiseException(record: *mut rtl::seh::ExceptionRecord) {
        // SAFETY: the caller's record.
        RAISED.with(|raised| raised.borrow_mut().push(unsafe { *record }));
    }

    /// RtlUnwind: the target and the record kept (no frames to unwind).
    pub unsafe extern "system" fn RtlUnwind(
        target: u32,
        _ip: u32,
        record: *mut rtl::seh::ExceptionRecord,
        _value: u32,
    ) {
        // SAFETY: the caller's record.
        UNWOUND.with(|calls| calls.borrow_mut().push((target, unsafe { *record })));
    }

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
    /// structure), each at its size.
    pub unsafe extern "system" fn NtQuerySystemInformation(
        class: u32,
        information: *mut u8,
        length: u32,
        _return_length: *mut u32,
    ) -> u32 {
        let status = answer();
        if status != 0 {
            return status;
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

    /// NtQueryInformationProcess: the current process's VM counters (class 3), its virtual size
    /// [`VIRTUAL_SIZE`].
    pub unsafe extern "system" fn NtQueryInformationProcess(
        process: u32,
        class: u32,
        information: *mut u8,
        length: u32,
        _returned: *mut u32,
    ) -> u32 {
        let status = answer();
        if status != 0 {
            return status;
        }
        if process != CURRENT_PROCESS {
            return STATUS_INVALID_HANDLE;
        }
        match (class, length) {
            (3, 44) => {
                // SAFETY: the caller's VM_COUNTERS.
                unsafe {
                    information.write_bytes(0, 44);
                    words(information, &[VIRTUAL_SIZE, VIRTUAL_SIZE]);
                }
                0
            }
            (3, _) => rtl::status::STATUS_INFO_LENGTH_MISMATCH,
            _ => rtl::status::STATUS_INVALID_INFO_CLASS,
        }
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
    }

    /// The base the allocation and view stand-ins hand back.
    pub const BASE: usize = 0x0034_0000;
    /// The handle the create and open stand-ins hand out.
    pub const HANDLE: u32 = 0x44;

    pub unsafe extern "system" fn NtAllocateVirtualMemory(
        _process: u32,
        base: *mut usize,
        _zero_bits: u32,
        size: *mut usize,
        kind: u32,
        _protect: u32,
    ) -> u32 {
        // SAFETY: the caller's in/out values.
        unsafe {
            LAST_VM.with(|cell| cell.set(Some((base.read(), size.read(), kind))));
            let status = answer();
            if status != 0 {
                return status;
            }
            base.write(BASE);
        }
        0
    }

    pub unsafe extern "system" fn NtFreeVirtualMemory(
        _process: u32,
        base: *mut usize,
        size: *mut usize,
        kind: u32,
    ) -> u32 {
        // SAFETY: the caller's in/out values.
        LAST_VM.with(|cell| cell.set(Some(unsafe { (base.read(), size.read(), kind) })));
        answer()
    }

    pub unsafe extern "system" fn NtProtectVirtualMemory(
        _process: u32,
        base: *mut usize,
        size: *mut usize,
        protect: u32,
        old: *mut u32,
    ) -> u32 {
        // SAFETY: the caller's in/out values.
        LAST_VM.with(|cell| cell.set(Some(unsafe { (base.read(), size.read(), protect) })));
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

    /// The units of a UNICODE_STRING.
    unsafe fn units<'a>(string: *const super::UnicodeString) -> &'a [u16] {
        // SAFETY: the caller's string.
        let string = unsafe { &*string };
        if string.length == 0 {
            return &[];
        }
        // SAFETY: as above.
        unsafe { core::slice::from_raw_parts(string.buffer, string.length as usize / 2) }
    }

    /// A create or open: the name recorded, the handle handed out, the arranged status (an
    /// informational one, STATUS_OBJECT_NAME_EXISTS, still hands the handle out).
    unsafe fn opened(handle: *mut u32, attributes: *const super::ObjectAttributes) -> u32 {
        // SAFETY: the caller's attributes and their name, when given.
        let name = unsafe {
            attributes.as_ref().and_then(|attributes| {
                attributes
                    .object_name
                    .as_ref()
                    .map(|name| (attributes.root_directory, units(name).to_vec()))
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

    pub unsafe extern "system" fn NtCreateSection(
        handle: *mut u32,
        access: u32,
        attributes: *const super::ObjectAttributes,
        maximum: *const i64,
        protect: u32,
        allocation: u32,
        file: u32,
    ) -> u32 {
        // SAFETY: the caller's maximum size, when given.
        let maximum = (!maximum.is_null()).then(|| unsafe { maximum.read() });
        LAST_SECTION.with(|cell| cell.set(Some((access, protect, allocation, file, maximum))));
        // SAFETY: the caller's arguments.
        unsafe { opened(handle, attributes) }
    }

    pub unsafe extern "system" fn NtOpenSection(
        handle: *mut u32,
        _access: u32,
        attributes: *const super::ObjectAttributes,
    ) -> u32 {
        // SAFETY: the caller's arguments.
        unsafe { opened(handle, attributes) }
    }

    pub unsafe extern "system" fn NtMapViewOfSection(
        _section: u32,
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
        // SAFETY: the caller's in/out values.
        LAST_VM.with(|cell| cell.set(Some(unsafe { (offset.read() as usize, size.read(), protect) })));
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

    /// The writes the console showed since the last look.
    pub fn console_writes() -> std::vec::Vec<(u32, std::vec::Vec<u8>)> {
        CONSOLE.with(|console| std::mem::take(&mut *console.borrow_mut()))
    }

    /// The host's screen: what a write shows is recorded with its handle; an address at or above
    /// 0x8000_0000 is refused as the kernel's probe refuses it, 0x10 as an unmapped page.
    struct Screen(u32);

    impl rtl::console::Screen for Screen {
        fn write(&mut self, buffer: usize, count: usize) -> Result<(), u32> {
            match buffer {
                0x8000_0000..=0xFFFF_FFFF => Err(rtl::status::STATUS_ACCESS_VIOLATION),
                0x10 => Err(0xC000_00E8),
                _ => {
                    // SAFETY: the test's buffer of `count` bytes.
                    let bytes =
                        unsafe { core::slice::from_raw_parts(buffer as *const u8, count) }.to_vec();
                    CONSOLE.with(|console| console.borrow_mut().push((self.0, bytes)));
                    Ok(())
                }
            }
        }
    }

    /// CsrClientCallServer, over the console server's own rules (`rtl::console`, as the kernel
    /// serves them): the data words the length names, answered in place; the ReturnValue.
    pub unsafe extern "system" fn CsrClientCallServer(
        message: *mut super::ApiMessage,
        capture_buffer: *mut u8,
        api: u32,
        length: u32,
    ) -> u32 {
        // SAFETY: the caller's message.
        let message = unsafe { &mut *message };
        let words = length as usize / core::mem::size_of::<usize>();
        let mut handles = CONSOLE_HANDLES.with(Cell::get);
        let status = rtl::console::serve(
            &mut handles,
            &mut Screen(message.data[0] as u32),
            api,
            &mut message.data[..words],
        );
        CONSOLE_HANDLES.with(|cell| cell.set(handles));
        message.capture_buffer = capture_buffer as usize;
        message.api_number = api;
        message.return_value = status;
        status
    }
}

/// The host tests' process: a PEB, process parameters and TEB laid out as the kernel lays them out
/// (`kernel/src/user/teb.rs`, `user/params.rs`).
#[cfg(test)]
pub mod threads {
    /// The process's stand-in pages.
    pub struct HostProcess {
        pub peb: usize,
        pub parameters: usize,
        pub teb: usize,
    }

    /// The command line the stand-in parameters carry (its last character the euro sign, byte 0x80
    /// in code page 1252).
    pub const COMMAND_LINE: &str = "C:\\RET0.EXE args \"two words\" \u{20AC}";
    /// The image path the stand-in parameters carry.
    pub const IMAGE_PATH: &str = "C:\\CORPUS\\RET0.EXE";
    /// The image's base, the PEB's ImageBaseAddress.
    pub const IMAGE_BASE: u32 = 0x0040_0000;
    /// Where the stand-in PEB's CSDVersion buffer sits on its page.
    const CSD_VERSION_BUFFER: usize = 0xA00;

    fn page(bytes: usize) -> usize {
        std::boxed::Box::leak(std::vec![0u32; bytes / 4].into_boxed_slice()).as_mut_ptr() as usize
    }

    fn put(at: usize, value: u32) {
        // SAFETY: inside a leaked stand-in page.
        unsafe { (at as *mut u32).write(value) }
    }

    fn pointer(at: usize, value: usize) {
        crate::base::write_pointer(at, value)
    }

    fn put_units(at: usize, text: &str) -> u32 {
        let units: std::vec::Vec<u16> = text.encode_utf16().collect();
        // SAFETY: inside a leaked stand-in page.
        unsafe { core::ptr::copy_nonoverlapping(units.as_ptr(), at as *mut u16, units.len()) };
        2 * units.len() as u32
    }

    impl HostProcess {
        /// The kernel's process at its start (`user::teb::peb_words`, `user::params::header`): the
        /// image's base, the version fields and the service pack's name; the parameters' standard
        /// handles, image path, command line and startup values; the TEB's self and PEB pointers.
        fn new() -> HostProcess {
            let (peb, parameters, teb) = (page(0x1000), page(0x2000), page(0x1000));
            put(peb + 0x08, IMAGE_BASE);
            pointer(peb + 0x10, parameters);
            put(peb + 0xA4, 5);
            put(peb + 0xA8, 0);
            put(peb + 0xAC, 2195 | 0x0400 << 16);
            put(peb + 0xB0, 2);
            let length = put_units(peb + CSD_VERSION_BUFFER, "Service Pack 4");
            put(peb + 0x1DC, length | (length + 2) << 16);
            pointer(peb + 0x1E0, peb + CSD_VERSION_BUFFER);
            for (at, value) in [
                (0x18, 3),
                (0x1C, 7),
                (0x20, 0xB),
                (0x50, 1),
                (0x54, 100),
                (0x58, 100),
                (0x6C, 1),
            ] {
                put(parameters + at, value);
            }
            let length = put_units(parameters + 0x498, IMAGE_PATH);
            put(parameters + 0x38, length | 520 << 16);
            pointer(parameters + 0x3C, parameters + 0x498);
            let length = put_units(parameters + 0x1000, COMMAND_LINE);
            put(parameters + 0x40, length | 0x800 << 16);
            pointer(parameters + 0x44, parameters + 0x1000);
            pointer(teb + 0x18, teb);
            pointer(teb + 0x30, peb);
            HostProcess {
                peb,
                parameters,
                teb,
            }
        }
    }

    std::thread_local! {
        static PROCESS: &'static HostProcess = std::boxed::Box::leak(std::boxed::Box::new(HostProcess::new()));
    }

    /// The calling test thread's process.
    pub fn process() -> &'static HostProcess {
        PROCESS.with(|process| *process)
    }
}
