//! kernel32's seam to ntdll: the system services and runtime-library functions its code calls,
//! imported from ntdll.dll by name as Windows 2000's kernel32 imports them (kernel32's only import
//! is ntdll). The host tests replace the imports with stand-ins of the same shape ([`host`]), over
//! a process laid out as the kernel lays one out ([`threads`]).
//!
//! An import is declared in the raw-dylib block below; its stand-in, of the same signature, in
//! [`host`]. A stand-in records what it was given in thread-locals and fails on demand
//! ([`host::FAIL_NEXT`]).

/// The console call's message, Windows 2000's shape: the LPC header, the capture buffer, the API
/// number, the server's answer, then the API's data (see `rtl::console`: F2K's console server's
/// dwords, pointer-sized so the host tests' buffers are host addresses).
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
    /// time zone, class 44).
    pub fn NtQuerySystemInformation(
        class: u32,
        information: *mut u8,
        length: u32,
        return_length: *mut u32,
    ) -> u32;
    /// NtQueryPerformanceCounter: the counter and, when asked, its frequency.
    pub fn NtQueryPerformanceCounter(counter: *mut u64, frequency: *mut u64) -> u32;
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

    /// NtQuerySystemInformation, as the kernel answers it: the time zone (44: no zone, a zero
    /// structure) at its size.
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
        assert_eq!(
            (class, length),
            (44, 172),
            "the stand-in answers the time zone at its size"
        );
        // SAFETY: the caller's buffer of `length` bytes.
        unsafe { information.write_bytes(0, length as usize) };
        0
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
