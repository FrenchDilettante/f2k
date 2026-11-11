//! user32's seam to the rest of the system: what its code calls, imported by name as Windows 2000's
//! user32 imports it (ntdll and kernel32), win32k's services through user32's own stubs (as
//! Windows 2000's user32 enters the kernel itself), the process heap through the PEB, and the
//! memory probe its stub routine reads arguments through (its import table holds no memory query).
//! The host tests replace the imports with stand-ins of the same shape ([`host`]).
//!
//! Each import is wrapped once here in a safe function over references and slices, a service's
//! failure an `Err` of its status; the only `unsafe` the rest of the DLL's code reaches for an
//! import is here. Memory a service writes for the caller is a [`UserBuffer`], handed to the
//! kernel unread; memory it only reads, or writes as a structure the caller gave the address of, is
//! handed over as its address (`usize`, zero for none), never dereferenced here. The window
//! procedures and callbacks the program registered are called here too ([`call_procedure`],
//! [`call_monitor_procedure`]): the kernel answers their addresses, it never calls them itself.
//!
//! One import is not Windows 2000's: ntdll's DbgPrint, which the stub routine logs through
//! (`scripts/compat.py` tolerates exactly that one, for the stubs' log line).

use core::ffi::CStr;
use core::marker::PhantomData;
use core::ptr::NonNull;

use rtl::accel::Accel;
use rtl::display::DevModeW;
use rtl::gdi::Rect;
use rtl::heap::HEAP_ZERO_MEMORY;
use rtl::icon::CursorData;
use rtl::menu::{MenuItemAnswer, MenuItemInfoW};
use rtl::pod::Pod;
use rtl::status::NtStatus;
use rtl::user::{Msg, Receipt};

use crate::class::WndClassExW;
use crate::Out;

#[cfg(all(target_arch = "x86", not(test)))]
mod raw {
    use rtl::accel::Accel;
    use rtl::display::DevModeW;
    use rtl::gdi::Rect;
    use rtl::icon::CursorData;
    use rtl::user::{Msg, Receipt};

    use crate::class::WndClassExW;

    #[link(
        name = "kernel32",
        kind = "raw-dylib",
        import_name_type = "undecorated"
    )]
    unsafe extern "system" {
        /// SetLastError: the calling thread's last error.
        pub fn SetLastError(code: u32);
        /// FindResourceExW: the HRSRC of a module's resource of a type, a name and a language
        /// (NULL: the program's module); NULL, the last error set, when there is none.
        pub fn FindResourceExW(
            module: usize,
            kind: *const u16,
            name: *const u16,
            language: u32,
        ) -> usize;
        /// FindResourceExA: FindResourceExW's, its type and name ANSI strings or numbers.
        pub fn FindResourceExA(
            module: usize,
            kind: *const u8,
            name: *const u8,
            language: u32,
        ) -> usize;
        /// LoadResource: the handle of an HRSRC's data; NULL, the last error set, when it fails.
        pub fn LoadResource(module: usize, resource: usize) -> usize;
        /// SizeofResource: an HRSRC's data's size in bytes; 0, the last error set, when it fails.
        pub fn SizeofResource(module: usize, resource: usize) -> u32;
        /// LockResource: the address of the data LoadResource's handle names.
        pub fn LockResource(data: usize) -> usize;
        /// GlobalAlloc, GlobalLock, GlobalUnlock, GlobalSize and GlobalFree: a global memory
        /// block (NULL, the last error set, when there is no room), its data's address while it
        /// is locked (NULL for a handle naming no block), its unlock, its size (0 for no block),
        /// and its release (NULL on success).
        pub fn GlobalAlloc(flags: u32, bytes: usize) -> usize;
        pub fn GlobalLock(memory: usize) -> *mut u8;
        pub fn GlobalUnlock(memory: usize) -> u32;
        pub fn GlobalSize(memory: usize) -> usize;
        pub fn GlobalFree(memory: usize) -> usize;
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
        /// RtlMultiByteToUnicodeN: the ANSI code page to UTF-16, what fits.
        pub fn RtlMultiByteToUnicodeN(
            unicode: *mut u16,
            max_bytes: u32,
            bytes_written: *mut u32,
            multi_byte: *const u8,
            multi_byte_bytes: u32,
        ) -> u32;
        /// CsrClientCallServer: a message to csrss's servers (F2K: the kernel's stand-in), its
        /// API's data answered in place; the server's status.
        pub fn CsrClientCallServer(
            message: *mut rtl::console::CsrApiMsg,
            capture_buffer: *mut u8,
            api: u32,
            length: u32,
        ) -> u32;
        /// NtClose: the handle closed (a DC's: the DC goes with it).
        pub fn NtClose(handle: usize) -> u32;
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
        /// NtUserChangeDisplaySettings: ChangeDisplaySettingsExW's change, answered with its
        /// DISP_CHANGE code.
        #[link_name = "\u{1}_f2k_nt_NtUserChangeDisplaySettings"]
        pub fn NtUserChangeDisplaySettings(
            device: *const u16,
            dev_mode: *const DevModeW,
            window: usize,
            flags: u32,
            param: usize,
        ) -> i32;

        // The window classes (kernel/src/win32k/class.rs).
        #[link_name = "\u{1}_f2k_nt_NtUserRegisterClassExWOW"]
        pub fn NtUserRegisterClassExWOW(
            class: *const WndClassExW,
            name: usize,
            flags: u32,
            atom: *mut u32,
            wow: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserUnregisterClass"]
        pub fn NtUserUnregisterClass(name: usize, instance: usize) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserGetClassInfo"]
        pub fn NtUserGetClassInfo(instance: usize, name: usize, class: *mut WndClassExW) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserGetClassName"]
        pub fn NtUserGetClassName(window: usize, name: *mut u8, max: u32, copied: *mut u32) -> u32;

        // The windows (kernel/src/win32k/window.rs).
        #[link_name = "\u{1}_f2k_nt_NtUserCreateWindowEx"]
        pub fn NtUserCreateWindowEx(
            ex_style: u32,
            class: usize,
            name: usize,
            style: u32,
            x: i32,
            y: i32,
            cx: i32,
            cy: i32,
            parent: usize,
            menu: usize,
            instance: usize,
            param: usize,
            version: u32,
            window: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserDestroyWindow"]
        pub fn NtUserDestroyWindow(window: usize) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserQueryWindow"]
        pub fn NtUserQueryWindow(window: usize, index: u32, answer: *mut u8, length: u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserSetWindowPos"]
        pub fn NtUserSetWindowPos(
            window: usize,
            insert_after: usize,
            x: i32,
            y: i32,
            cx: i32,
            cy: i32,
            flags: u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserMoveWindow"]
        pub fn NtUserMoveWindow(
            window: usize,
            x: i32,
            y: i32,
            cx: i32,
            cy: i32,
            repaint: u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserShowWindow"]
        pub fn NtUserShowWindow(window: usize, command: i32, previous: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserShowWindowAsync"]
        pub fn NtUserShowWindowAsync(window: usize, command: i32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserSetWindowLong"]
        pub fn NtUserSetWindowLong(
            window: usize,
            index: i32,
            value: u32,
            ansi: u32,
            previous: *mut u32,
            previous_ansi: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserSetWindowWord"]
        pub fn NtUserSetWindowWord(
            window: usize,
            index: i32,
            value: u32,
            previous: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserDefSetText"]
        pub fn NtUserDefSetText(window: usize, text: usize) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserChildWindowFromPointEx"]
        pub fn NtUserChildWindowFromPointEx(
            parent: usize,
            x: i32,
            y: i32,
            flags: u32,
            child: *mut u32,
        ) -> u32;

        // The clipboard (kernel/src/win32k/clipboard.rs).
        #[link_name = "\u{1}_f2k_nt_NtUserOpenClipboard"]
        pub fn NtUserOpenClipboard(window: usize) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserCloseClipboard"]
        pub fn NtUserCloseClipboard() -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserEmptyClipboard"]
        pub fn NtUserEmptyClipboard() -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserConvertMemHandle"]
        pub fn NtUserConvertMemHandle(data: usize, length: u32, handle: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserSetClipboardData"]
        pub fn NtUserSetClipboardData(format: u32, data: u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserGetClipboardData"]
        pub fn NtUserGetClipboardData(format: u32, data: *mut u32, length: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserCreateLocalMemHandle"]
        pub fn NtUserCreateLocalMemHandle(
            data: u32,
            buffer: *mut u8,
            length: u32,
            needed: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserIsClipboardFormatAvailable"]
        pub fn NtUserIsClipboardFormatAvailable(format: u32, available: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserCountClipboardFormats"]
        pub fn NtUserCountClipboardFormats(count: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserGetClipboardOwner"]
        pub fn NtUserGetClipboardOwner(window: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserGetOpenClipboardWindow"]
        pub fn NtUserGetOpenClipboardWindow(window: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserRegisterWindowMessage"]
        pub fn NtUserRegisterWindowMessage(name: usize, atom: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserGetClipboardFormatName"]
        pub fn NtUserGetClipboardFormatName(
            format: u32,
            name: *mut u8,
            max: u32,
            copied: *mut u32,
        ) -> u32;

        // The menus, the accelerators, the cursors and icons (kernel/src/win32k/menu.rs,
        // accel.rs, icon.rs).
        #[link_name = "\u{1}_f2k_nt_NtUserCallNoParam"]
        pub fn NtUserCallNoParam(routine: u32, result: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserThunkedMenuItemInfo"]
        pub fn NtUserThunkedMenuItemInfo(
            menu: usize,
            item: u32,
            flags: u32,
            operation: u32,
            info: *mut u8,
            text: *const u16,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserDestroyMenu"]
        pub fn NtUserDestroyMenu(menu: usize) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserCheckMenuItem"]
        pub fn NtUserCheckMenuItem(menu: usize, item: u32, check: u32, previous: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserEnableMenuItem"]
        pub fn NtUserEnableMenuItem(menu: usize, item: u32, enable: u32, previous: *mut u32)
            -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserSetMenu"]
        pub fn NtUserSetMenu(window: usize, menu: usize, repaint: u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserCreateAcceleratorTable"]
        pub fn NtUserCreateAcceleratorTable(
            entries: *const Accel,
            count: u32,
            module: usize,
            resource: usize,
            table: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserCopyAcceleratorTable"]
        pub fn NtUserCopyAcceleratorTable(
            table: usize,
            entries: *mut Accel,
            count: u32,
            copied: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserDestroyAcceleratorTable"]
        pub fn NtUserDestroyAcceleratorTable(table: usize, destroyed: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserTranslateAccelerator"]
        pub fn NtUserTranslateAccelerator(
            window: usize,
            table: usize,
            msg: *const Msg,
            translated: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserFindExistingCursorIcon"]
        pub fn NtUserFindExistingCursorIcon(
            module: usize,
            resource: usize,
            size: u32,
            kind: u32,
            cursor: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserSetCursorIconData"]
        pub fn NtUserSetCursorIconData(cursor: usize, data: *const CursorData) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserGetIconInfo"]
        pub fn NtUserGetIconInfo(cursor: usize, data: *mut CursorData) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserDestroyCursor"]
        pub fn NtUserDestroyCursor(cursor: usize) -> u32;

        // The queues and the painting (kernel/src/win32k/queue.rs, paint.rs).
        #[link_name = "\u{1}_f2k_nt_NtUserPostMessage"]
        pub fn NtUserPostMessage(window: usize, message: u32, wparam: u32, lparam: i32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserPostThreadMessage"]
        pub fn NtUserPostThreadMessage(thread: u32, message: u32, wparam: u32, lparam: i32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserGetMessage"]
        pub fn NtUserGetMessage(receipt: *mut Receipt, window: usize, min: u32, max: u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserPeekMessage"]
        pub fn NtUserPeekMessage(
            receipt: *mut Receipt,
            window: usize,
            min: u32,
            max: u32,
            flags: u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserMessageCall"]
        pub fn NtUserMessageCall(
            window: usize,
            message: u32,
            wparam: u32,
            lparam: i32,
            proc: *mut u32,
            result: *mut i32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserDispatchMessage"]
        pub fn NtUserDispatchMessage(msg: *const Msg, proc: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserCallOneParam"]
        pub fn NtUserCallOneParam(param: u32, routine: u32, result: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserCallHwndLock"]
        pub fn NtUserCallHwndLock(window: usize, routine: u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserInvalidateRect"]
        pub fn NtUserInvalidateRect(window: usize, rect: usize, erase: u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserValidateRect"]
        pub fn NtUserValidateRect(window: usize, rect: usize) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserGetUpdateRect"]
        pub fn NtUserGetUpdateRect(window: usize, rect: usize, erase: u32, result: *mut u32)
            -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserBeginPaint"]
        pub fn NtUserBeginPaint(window: usize, paint: usize) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserEndPaint"]
        pub fn NtUserEndPaint(window: usize, paint: usize) -> u32;

        // The focus and activation (kernel/src/win32k/focus.rs).
        #[link_name = "\u{1}_f2k_nt_NtUserSetFocus"]
        pub fn NtUserSetFocus(window: usize, previous: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserSetActiveWindow"]
        pub fn NtUserSetActiveWindow(window: usize, previous: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserGetForegroundWindow"]
        pub fn NtUserGetForegroundWindow(window: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserGetThreadState"]
        pub fn NtUserGetThreadState(routine: u32, result: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserCallHwndParamLock"]
        pub fn NtUserCallHwndParamLock(
            window: usize,
            param: u32,
            routine: u32,
            result: *mut u32,
        ) -> u32;

        // The DCs (kernel/src/win32k/dc.rs).
        #[link_name = "\u{1}_f2k_nt_NtUserGetDC"]
        pub fn NtUserGetDC(window: usize, dc: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserGetDCEx"]
        pub fn NtUserGetDCEx(window: usize, region: usize, flags: u32, dc: *mut u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserGetWindowDC"]
        pub fn NtUserGetWindowDC(window: usize, dc: *mut u32) -> u32;

        // The display (kernel/src/win32k/display.rs).
        #[link_name = "\u{1}_f2k_nt_NtUserEnumDisplaySettings"]
        pub fn NtUserEnumDisplaySettings(
            device: usize,
            mode: u32,
            dev_mode: usize,
            flags: u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserEnumDisplayDevices"]
        pub fn NtUserEnumDisplayDevices(device: usize, number: u32, out: usize, flags: u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserEnumDisplayMonitors"]
        pub fn NtUserEnumDisplayMonitors(
            dc: usize,
            clip: usize,
            monitors: *mut u32,
            rects: *mut Rect,
            count: u32,
            found: *mut u32,
        ) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserSetSysColors"]
        pub fn NtUserSetSysColors(count: u32, indexes: usize, colors: usize, flags: u32) -> u32;
        #[link_name = "\u{1}_f2k_nt_NtUserSystemParametersInfo"]
        pub fn NtUserSystemParametersInfo(
            action: u32,
            ui_param: u32,
            param: usize,
            win_ini: u32,
        ) -> u32;
    }

    /// The process heap (the PEB's ProcessHeap).
    pub fn process_heap() -> usize {
        rtl::sys::process_heap_handle()
    }

    /// Call the window procedure (or a TimerProc: the same shape) at `proc` with a message.
    ///
    /// # Safety
    ///
    /// `proc` is the address of a function of the WNDPROC shape: one the program registered or
    /// handed over (a class's lpfnWndProc, a timer's TimerProc), as the kernel answers it.
    pub unsafe fn call_procedure(
        proc: u32,
        window: u32,
        message: u32,
        wparam: u32,
        lparam: i32,
    ) -> i32 {
        type WndProc = unsafe extern "system" fn(u32, u32, u32, i32) -> i32;
        // SAFETY: the caller's contract: a nonzero address of a WNDPROC-shaped function.
        let proc = unsafe { core::mem::transmute::<usize, WndProc>(proc as usize) };
        // SAFETY: as above; the program's own code, called as Windows calls it.
        unsafe { proc(window, message, wparam, lparam) }
    }

    /// Call EnumDisplayMonitors' callback at `proc` with a monitor.
    ///
    /// # Safety
    ///
    /// `proc` is the address of a MonitorEnumProc the program handed over; `rect` lives for the
    /// call.
    pub unsafe fn call_monitor_procedure(
        proc: u32,
        monitor: u32,
        dc: usize,
        rect: *const Rect,
        data: usize,
    ) -> u32 {
        type MonitorEnumProc = unsafe extern "system" fn(u32, usize, *const Rect, usize) -> u32;
        // SAFETY: the caller's contract: a nonzero address of a MonitorEnumProc.
        let proc = unsafe { core::mem::transmute::<usize, MonitorEnumProc>(proc as usize) };
        // SAFETY: as above; the program's own code, called as Windows calls it.
        unsafe { proc(monitor, dc, rect, data) }
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

impl<'a> From<&'a mut [u16]> for UserBuffer<'a> {
    /// A buffer of UTF-16 units of this DLL's own, lent to the service (its length in bytes).
    fn from(units: &'a mut [u16]) -> Self {
        UserBuffer {
            at: units.as_mut_ptr().cast(),
            length: 2 * units.len() as u32,
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

    /// The block's bytes as UTF-16 units, to write (an odd last byte left out).
    pub fn units_mut(&mut self) -> &mut [u16] {
        // SAFETY: the heap's blocks are 8-aligned (its granularity); the block holds `size`
        // initialized (zeroed) bytes, ours alone while it lives, any of which make a unit.
        unsafe { core::slice::from_raw_parts_mut(self.at.as_ptr().cast(), self.size / 2) }
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

/// A resource FindResourceExW found: its HRSRC (kernel32's handle, never zero).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hrsrc(usize);

/// FindResourceExW, for a numbered type and name (MAKEINTRESOURCE: no string to read): the
/// resource of type `kind` numbered `name` in `language`, in the module `module` (NULL: the
/// program's); none, with kernel32's last error, when the module has none.
pub fn find_resource(module: usize, kind: u16, name: u16, language: u16) -> Option<Hrsrc> {
    // SAFETY: the type and the name are numbers in a pointer's place (their high word zero),
    // which kernel32 takes as numbers; it dereferences neither.
    let found = unsafe {
        raw::FindResourceExW(
            module,
            kind as usize as *const u16,
            name as usize as *const u16,
            language as u32,
        )
    };
    (found != 0).then_some(Hrsrc(found))
}

/// LoadResource, SizeofResource and LockResource: the data of the resource `resource` of the
/// module `module` (as [`find_resource`] found it there), where it lies in the module's mapped
/// image; none, with kernel32's last error, when it cannot be loaded.
///
/// The data stays mapped for as long as the module stays loaded: the slice's `'static` stands
/// for that. Its callers hold it only for the call that found it, whose caller keeps the module
/// it named loaded meanwhile, as the platform's resource calls presume.
pub fn resource_data(module: usize, resource: Hrsrc) -> Option<&'static [u8]> {
    // SAFETY: no pointers; an HRSRC kernel32 answered for this module.
    let data = unsafe { raw::LoadResource(module, resource.0) };
    if data == 0 {
        return None;
    }
    // SAFETY: as above; then LoadResource's handle, which LockResource takes as it is.
    let (size, at) = unsafe {
        (
            raw::SizeofResource(module, resource.0),
            raw::LockResource(data),
        )
    };
    if size == 0 || at == 0 {
        return Some(&[]);
    }
    // SAFETY: kernel32 answers the address and the size of the resource's data in the module's
    // mapped image, which nothing writes and which stays mapped while the module is loaded (see
    // above); bytes need no alignment.
    Some(unsafe { core::slice::from_raw_parts(at as *const u8, size as usize) })
}

/// A resource's name as LoadMenu, LoadAccelerators and LoadIcon take it: a number in a pointer's
/// place (its high word zero), or a NUL-terminated string's address (`"#200"` names number 200:
/// kernel32 reads it so), UTF-16 for the W calls and ANSI for the A calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceName {
    Wide(usize),
    Narrow(usize),
}

impl ResourceName {
    /// The number it names, when it is one.
    pub fn id(self) -> Option<u16> {
        let raw = match self {
            ResourceName::Wide(raw) | ResourceName::Narrow(raw) => raw,
        };
        (raw >> 16 == 0).then_some(raw as u16)
    }
}

/// FindResourceExW, or FindResourceExA for an ANSI name: the resource of type `kind` named `name`,
/// in the module `module` (NULL: the program's), in language 0 (FindResource's search); none, with
/// kernel32's last error, when the module has none.
///
/// # Safety
///
/// A string name is the address of a NUL-terminated string the call may read.
pub unsafe fn find_named_resource(module: usize, kind: u16, name: ResourceName) -> Option<Hrsrc> {
    // SAFETY: the type is a number in a pointer's place, which kernel32 takes as a number; the
    // name is a number, or the caller's string (the contract).
    let found = unsafe {
        match name {
            ResourceName::Wide(raw) => {
                raw::FindResourceExW(module, kind as usize as *const u16, raw as *const u16, 0)
            }
            ResourceName::Narrow(raw) => {
                raw::FindResourceExA(module, kind as usize as *const u8, raw as *const u8, 0)
            }
        }
    };
    (found != 0).then_some(Hrsrc(found))
}

/// GlobalAlloc: a global memory block of `bytes` bytes, as the GMEM_ `flags` ask: its handle; none,
/// with kernel32's last error, when there is no room.
pub fn global_alloc(flags: u32, bytes: usize) -> Option<usize> {
    // SAFETY: no pointers.
    let memory = unsafe { raw::GlobalAlloc(flags, bytes) };
    (memory != 0).then_some(memory)
}

/// GlobalSize: the size of the block `memory` names; 0 for a handle naming none.
pub fn global_size(memory: usize) -> usize {
    // SAFETY: kernel32 checks the handle against its table and the heap before it reads anything.
    unsafe { raw::GlobalSize(memory) }
}

/// GlobalFree: the block `memory` names freed (a handle naming none refused by kernel32).
pub fn global_free(memory: usize) {
    // SAFETY: as for `global_size`.
    unsafe { raw::GlobalFree(memory) };
}

/// A global memory block locked while this lives (GlobalLock, then GlobalUnlock when dropped): its
/// data's address and size, handed to a service unread.
pub struct GlobalLocked {
    memory: usize,
    at: NonNull<u8>,
    size: usize,
}

impl GlobalLocked {
    /// The block `memory` names, locked; none for a handle naming no block (or a discarded one).
    pub fn new(memory: usize) -> Option<GlobalLocked> {
        // SAFETY: kernel32 checks the handle before it reads anything; the lock is undone once,
        // when the value is dropped.
        let at = NonNull::new(unsafe { raw::GlobalLock(memory) })?;
        Some(GlobalLocked {
            memory,
            at,
            size: global_size(memory),
        })
    }

    /// The data's address.
    pub fn address(&self) -> usize {
        self.at.as_ptr() as usize
    }

    /// The block's size.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The data as a buffer a service writes.
    pub fn buffer(&mut self) -> UserBuffer<'_> {
        // SAFETY: the block's `size` bytes, kernel32's heap memory, locked for the borrow's life;
        // nothing in this DLL holds a reference into them.
        unsafe { UserBuffer::new(self.at.as_ptr(), self.size as u32) }
    }
}

impl Drop for GlobalLocked {
    fn drop(&mut self) {
        // SAFETY: the handle locked in `new`, unlocked once.
        unsafe { raw::GlobalUnlock(self.memory) };
    }
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

/// CsrClientCallServer: API `api`'s data `data` sent to its server (no capture buffer: F2K's server
/// reads the client's memory where it is), as the data after the message's header; the server's
/// status, `data` as the server answered it.
pub fn call_server(api: u32, data: &mut [u8]) -> u32 {
    use rtl::pod::Pod;
    let mut message = rtl::console::CsrApiMsg::default();
    let length = data.len();
    message.data.as_bytes_mut()[..length].copy_from_slice(data);
    // SAFETY: the message is this function's own, its data as long as the length says.
    unsafe { raw::CsrClientCallServer(&mut message, core::ptr::null_mut(), api, length as u32) };
    data.copy_from_slice(&message.data.as_bytes()[..length]);
    message.return_value
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

/// NtUserChangeDisplaySettings: the display change ChangeDisplaySettingsExW asks for (the
/// display's NUL-terminated name, null for the primary one; the DEVMODEW, null for the default
/// mode; the reserved window and parameter; the CDS_ flags), answered with its DISP_CHANGE code.
/// The two addresses (zero for none) are handed to the kernel unread: it reads them through its
/// fault-tolerant copies (a bad address fails the change), and nothing here dereferences them.
pub fn change_display_settings(
    device: usize,
    dev_mode: usize,
    window: usize,
    flags: u32,
    param: usize,
) -> i32 {
    // SAFETY: the kernel only reads the name and the DEVMODEW, through its fault-tolerant copies,
    // before the call returns; it writes no memory.
    unsafe {
        raw::NtUserChangeDisplaySettings(
            device as *const u16,
            dev_mode as *const DevModeW,
            window,
            flags,
            param,
        )
    }
}

/// RtlMultiByteToUnicodeN: as much of `source` as `destination` holds, from the ANSI code page to
/// UTF-16: the units written.
pub fn multi_byte_to_unicode(destination: &mut [u16], source: &[u8]) -> usize {
    let mut written = 0u32;
    // SAFETY: the call reads the source's bytes and writes at most the destination's units, and
    // the count into the local.
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

/// NtClose: `handle` closed.
pub fn close(handle: usize) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtClose(handle) })
}

// --- win32k: window classes ----------------------------------------------------------------------

/// NtUserRegisterClassExWOW: the class `class` describes, named `name` (a NUL-terminated UTF-16
/// string's address, or an integer atom), registered with the flags word `flags`: its atom. The
/// service answers a duplicate with STATUS_OBJECT_NAME_EXISTS, an informational status, so any
/// status but STATUS_SUCCESS is the registration's failure.
pub fn register_class(class: &WndClassExW, name: usize, flags: u32) -> Result<u16, NtStatus> {
    let (mut atom, mut wow) = (0u32, 0u32);
    // SAFETY: the kernel reads the structure, the name and the menu name it points at (this DLL's
    // own, or the caller's, alive for the call), and writes the two locals.
    let status = unsafe { raw::NtUserRegisterClassExWOW(class, name, flags, &mut atom, &mut wow) };
    if status != rtl::status::STATUS_SUCCESS {
        return Err(NtStatus(status));
    }
    Ok(atom as u16)
}

/// NtUserUnregisterClass: the class `name` (as [`register_class`] takes it) of the module
/// `instance` unregistered.
pub fn unregister_class(name: usize, instance: usize) -> Result<(), NtStatus> {
    // SAFETY: the kernel reads the name through its fault-tolerant copies.
    checked(unsafe { raw::NtUserUnregisterClass(name, instance) })
}

/// NtUserGetClassInfo: the fields of the class `name` (as [`register_class`] takes it) the module
/// `instance` sees, into `class`.
pub fn class_info(instance: usize, name: usize, class: &mut WndClassExW) -> Result<(), NtStatus> {
    // SAFETY: the kernel reads the name through its fault-tolerant copies, and reads and writes the
    // local structure.
    checked(unsafe { raw::NtUserGetClassInfo(instance, name, class) })
}

/// NtUserGetClassName: the name of `window`'s class, at most `max` units into `name` (its
/// terminator included); the units copied, the terminator not counted.
pub fn class_name(window: usize, name: UserBuffer, max: u32) -> Result<u32, NtStatus> {
    let mut copied = 0u32;
    // SAFETY: the kernel writes the buffer through its fault-tolerant copies (no memory this DLL
    // holds a reference into), and the count into the local.
    checked(unsafe { raw::NtUserGetClassName(window, name.at, max, &mut copied) })?;
    Ok(copied)
}

// --- win32k: windows -----------------------------------------------------------------------------

/// What NtUserCreateWindowEx takes: CreateWindowExW's arguments, the strings as the addresses of
/// NUL-terminated UTF-16 strings (the class name an integer atom when its high word is zero, the
/// window name zero for none), the private ANSI-creator bit in the extended style for a narrow
/// caller.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Creation {
    pub ex_style: u32,
    pub class: usize,
    pub name: usize,
    pub style: u32,
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
    pub parent: usize,
    pub menu: usize,
    pub instance: usize,
    pub param: usize,
    /// The Windows version the caller expects, its major version in the high word.
    pub version: u32,
}

/// NtUserCreateWindowEx: the window `creation` describes, made: its handle.
pub fn create_window(creation: &Creation) -> Result<u32, NtStatus> {
    let mut window = 0u32;
    let c = creation;
    // SAFETY: the kernel reads the two strings through its fault-tolerant copies (this DLL's own,
    // or the caller's, alive for the call), and writes the handle into the local.
    checked(unsafe {
        raw::NtUserCreateWindowEx(
            c.ex_style,
            c.class,
            c.name,
            c.style,
            c.x,
            c.y,
            c.cx,
            c.cy,
            c.parent,
            c.menu,
            c.instance,
            c.param,
            c.version,
            &mut window,
        )
    })?;
    Ok(window)
}

/// NtUserDestroyWindow: `window` destroyed.
pub fn destroy_window(window: usize) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtUserDestroyWindow(window) })
}

/// NtUserQueryWindow: what `index` (rtl::window's QUERY_ indexes) asks about `window`, into
/// `answer`, whose size is the answer's.
pub fn query_window<T: Pod>(window: usize, index: u32, answer: &mut T) -> Result<(), NtStatus> {
    let bytes = answer.as_bytes_mut();
    // SAFETY: the kernel writes the local answer, as long as its length.
    checked(unsafe {
        raw::NtUserQueryWindow(window, index, bytes.as_mut_ptr(), bytes.len() as u32)
    })
}

/// NtUserSetWindowPos: SetWindowPos's change.
#[allow(clippy::too_many_arguments)]
pub fn set_window_pos(
    window: usize,
    insert_after: usize,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    flags: u32,
) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtUserSetWindowPos(window, insert_after, x, y, cx, cy, flags) })
}

/// NtUserMoveWindow: MoveWindow's change.
pub fn move_window(
    window: usize,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    repaint: bool,
) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtUserMoveWindow(window, x, y, cx, cy, repaint as u32) })
}

/// NtUserShowWindow: ShowWindow's change, its answer (the window's visibility before it).
pub fn show_window(window: usize, command: i32) -> Result<u32, NtStatus> {
    let mut previous = 0u32;
    // SAFETY: the kernel writes the answer into the local.
    checked(unsafe { raw::NtUserShowWindow(window, command, &mut previous) })?;
    Ok(previous)
}

/// NtUserShowWindowAsync: ShowWindowAsync's change.
pub fn show_window_async(window: usize, command: i32) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtUserShowWindowAsync(window, command) })
}

/// NtUserSetWindowLong: SetWindowLong's change of `window`'s field at `index` (rtl::window's GWL_*,
/// or an offset into its extra bytes) to `value`, through the narrow entry point when `ansi`: the
/// value the field held, and for GWL_WNDPROC whether the procedure it held took the narrow forms
/// of the messages.
pub fn set_window_long(
    window: usize,
    index: i32,
    value: u32,
    ansi: bool,
) -> Result<(u32, bool), NtStatus> {
    let (mut previous, mut previous_ansi) = (0u32, 0u32);
    // SAFETY: the kernel writes the two locals.
    checked(unsafe {
        raw::NtUserSetWindowLong(
            window,
            index,
            value,
            ansi as u32,
            &mut previous,
            &mut previous_ansi,
        )
    })?;
    Ok((previous, previous_ansi != 0))
}

/// NtUserSetWindowWord: SetWindowWord's change of the word at `index` in `window`'s extra bytes to
/// `value`: the word it held.
pub fn set_window_word(window: usize, index: i32, value: u16) -> Result<u16, NtStatus> {
    let mut previous = 0u32;
    // SAFETY: the kernel writes the local.
    checked(unsafe { raw::NtUserSetWindowWord(window, index, value as u32, &mut previous) })?;
    Ok(previous as u16)
}

/// NtUserDefSetText: `window`'s text set to the NUL-terminated UTF-16 string at `text` (zero: the
/// empty text).
pub fn def_set_text(window: usize, text: usize) -> Result<(), NtStatus> {
    // SAFETY: the kernel reads the string through its fault-tolerant copies (this DLL's own, or the
    // caller's, alive for the call); it writes no memory.
    checked(unsafe { raw::NtUserDefSetText(window, text) })
}

/// NtUserChildWindowFromPointEx: the child of `parent` holding the point of its client area, as
/// the CWP_ flags pass over children: its handle, `parent` itself when none holds it, 0 for a point
/// outside `parent`.
pub fn child_window_from_point(parent: usize, x: i32, y: i32, flags: u32) -> Result<u32, NtStatus> {
    let mut child = 0u32;
    // SAFETY: the kernel writes the handle into the local.
    checked(unsafe { raw::NtUserChildWindowFromPointEx(parent, x, y, flags, &mut child) })?;
    Ok(child)
}

// --- win32k: the clipboard -----------------------------------------------------------------------

/// NtUserOpenClipboard: the clipboard open for the calling thread, with `window` (0 for none).
pub fn open_clipboard(window: usize) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtUserOpenClipboard(window) })
}

/// NtUserCloseClipboard: the clipboard closed.
pub fn close_clipboard() -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtUserCloseClipboard() })
}

/// NtUserEmptyClipboard: the clipboard emptied.
pub fn empty_clipboard() -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtUserEmptyClipboard() })
}

/// NtUserConvertMemHandle: a data object of the `length` bytes at `data` (a locked global memory
/// block's): its handle.
pub fn convert_mem_handle(data: usize, length: usize) -> Result<u32, NtStatus> {
    let mut handle = 0u32;
    // SAFETY: the kernel reads the bytes through its fault-tolerant copies, and writes the handle
    // into the local.
    checked(unsafe { raw::NtUserConvertMemHandle(data, length as u32, &mut handle) })?;
    Ok(handle)
}

/// NtUserSetClipboardData: the data object `data` put under `format`.
pub fn set_clipboard_data(format: u32, data: u32) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtUserSetClipboardData(format, data) })
}

/// NtUserGetClipboardData: `format`'s data object and its length (0 and 0 for none).
pub fn get_clipboard_data(format: u32) -> Result<(u32, usize), NtStatus> {
    let (mut data, mut length) = (0u32, 0u32);
    // SAFETY: the kernel writes the two locals.
    checked(unsafe { raw::NtUserGetClipboardData(format, &mut data, &mut length) })?;
    Ok((data, length as usize))
}

/// NtUserCreateLocalMemHandle: the data object `data`'s bytes into `buffer`.
pub fn create_local_mem_handle(data: u32, buffer: UserBuffer) -> Result<(), NtStatus> {
    let mut needed = 0u32;
    // SAFETY: the kernel writes the buffer through its fault-tolerant copies (no memory this DLL
    // holds a reference into), and the length into the local.
    checked(unsafe { raw::NtUserCreateLocalMemHandle(data, buffer.at, buffer.length, &mut needed) })
}

/// NtUserIsClipboardFormatAvailable: whether the clipboard has `format`.
pub fn is_clipboard_format_available(format: u32) -> Result<bool, NtStatus> {
    let mut available = 0u32;
    // SAFETY: the kernel writes the local.
    checked(unsafe { raw::NtUserIsClipboardFormatAvailable(format, &mut available) })?;
    Ok(available != 0)
}

/// NtUserCountClipboardFormats: how many formats the clipboard has.
pub fn count_clipboard_formats() -> Result<u32, NtStatus> {
    let mut count = 0u32;
    // SAFETY: the kernel writes the local.
    checked(unsafe { raw::NtUserCountClipboardFormats(&mut count) })?;
    Ok(count)
}

/// NtUserGetClipboardOwner: the clipboard's owner (0 for none).
pub fn clipboard_owner() -> Result<u32, NtStatus> {
    let mut window = 0u32;
    // SAFETY: the kernel writes the local.
    checked(unsafe { raw::NtUserGetClipboardOwner(&mut window) })?;
    Ok(window)
}

/// NtUserGetOpenClipboardWindow: the window the clipboard is open with (0 for none).
pub fn open_clipboard_window() -> Result<u32, NtStatus> {
    let mut window = 0u32;
    // SAFETY: the kernel writes the local.
    checked(unsafe { raw::NtUserGetOpenClipboardWindow(&mut window) })?;
    Ok(window)
}

/// NtUserRegisterWindowMessage: the atom of the NUL-terminated UTF-16 name at `name`.
pub fn register_window_message(name: usize) -> Result<u32, NtStatus> {
    let mut atom = 0u32;
    // SAFETY: the kernel reads the name through its fault-tolerant copies, and writes the local.
    checked(unsafe { raw::NtUserRegisterWindowMessage(name, &mut atom) })?;
    Ok(atom)
}

/// NtUserGetClipboardFormatName: the registered `format`'s name into `name` (its length in units
/// holding the NUL too, the name cut to fit): the units copied before the NUL.
pub fn clipboard_format_name(format: u32, name: UserBuffer) -> Result<u32, NtStatus> {
    let mut copied = 0u32;
    // SAFETY: the kernel writes the buffer through its fault-tolerant copies (no memory this DLL
    // holds a reference into), and the count into the local.
    checked(unsafe {
        raw::NtUserGetClipboardFormatName(format, name.at, name.length / 2, &mut copied)
    })?;
    Ok(copied)
}

// --- win32k: messages ----------------------------------------------------------------------------

/// NtUserPostMessage: a message posted to `window`'s thread.
pub fn post_message(window: usize, message: u32, wparam: u32, lparam: i32) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtUserPostMessage(window, message, wparam, lparam) })
}

/// NtUserPostThreadMessage: a message posted to the thread whose id is `thread`.
pub fn post_thread_message(
    thread: u32,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtUserPostThreadMessage(thread, message, wparam, lparam) })
}

/// NtUserGetMessage: the next message the filter takes, waiting for one, into `receipt`.
pub fn get_message(
    receipt: &mut Receipt,
    window: usize,
    min: u32,
    max: u32,
) -> Result<(), NtStatus> {
    // SAFETY: the kernel writes the local receipt.
    checked(unsafe { raw::NtUserGetMessage(receipt, window, min, max) })
}

/// NtUserPeekMessage: the next message the filter and `flags` (PM_*, the PM_QS_ kinds) take, into
/// `receipt` (RECEIVED_NONE when there is none).
pub fn peek_message(
    receipt: &mut Receipt,
    window: usize,
    min: u32,
    max: u32,
    flags: u32,
) -> Result<(), NtStatus> {
    // SAFETY: the kernel writes the local receipt.
    checked(unsafe { raw::NtUserPeekMessage(receipt, window, min, max, flags) })
}

/// NtUserMessageCall: SendMessage's kernel side: the window procedure to call for a window of the
/// calling thread's (nonzero), or 0 and the answer.
pub fn message_call(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> Result<(u32, i32), NtStatus> {
    let (mut proc, mut result) = (0u32, 0i32);
    // SAFETY: the kernel writes the two locals.
    checked(unsafe {
        raw::NtUserMessageCall(window, message, wparam, lparam, &mut proc, &mut result)
    })?;
    Ok((proc, result))
}

/// NtUserDispatchMessage: the procedure DispatchMessage calls with `msg` (0 for none).
pub fn dispatch_target(msg: &Msg) -> Result<u32, NtStatus> {
    let mut proc = 0u32;
    // SAFETY: the kernel reads the local message and writes the local procedure.
    checked(unsafe { raw::NtUserDispatchMessage(msg, &mut proc) })?;
    Ok(proc)
}

/// NtUserCallOneParam: the routine `routine` (rtl::user's ONE_PARAM_*) with `param`: its result.
pub fn call_one_param(param: u32, routine: u32) -> Result<u32, NtStatus> {
    let mut result = 0u32;
    // SAFETY: the kernel writes the local result.
    checked(unsafe { raw::NtUserCallOneParam(param, routine, &mut result) })?;
    Ok(result)
}

/// NtUserCallHwndLock: the routine `routine` (rtl::user's HWND_LOCK_*) on `window`.
pub fn call_hwnd_lock(window: usize, routine: u32) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtUserCallHwndLock(window, routine) })
}

/// The window procedure (or TimerProc) `proc` the kernel answered, called with a message: its
/// answer.
pub fn call_procedure(proc: u32, window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
    // SAFETY: `proc` is an address the kernel answered for the message: a window procedure a class
    // was registered with, or a TimerProc a timer was set with, both the program's own functions
    // of that shape.
    unsafe { raw::call_procedure(proc, window, message, wparam, lparam) }
}

// --- win32k: the focus and activation ------------------------------------------------------------

/// NtUserSetFocus: the focus to `window` (0: to no window); the window that had it (0 for none, or
/// for a refusal).
pub fn set_focus(window: usize) -> Result<u32, NtStatus> {
    let mut previous = 0u32;
    // SAFETY: the kernel writes the answer into the local.
    checked(unsafe { raw::NtUserSetFocus(window, &mut previous) })?;
    Ok(previous)
}

/// NtUserSetActiveWindow: `window` activated; the window that was active (0 for none, or for a
/// refusal).
pub fn set_active_window(window: usize) -> Result<u32, NtStatus> {
    let mut previous = 0u32;
    // SAFETY: the kernel writes the answer into the local.
    checked(unsafe { raw::NtUserSetActiveWindow(window, &mut previous) })?;
    Ok(previous)
}

/// NtUserGetForegroundWindow: the foreground window (0 for none).
pub fn foreground_window() -> Result<u32, NtStatus> {
    let mut window = 0u32;
    // SAFETY: the kernel writes the answer into the local.
    checked(unsafe { raw::NtUserGetForegroundWindow(&mut window) })?;
    Ok(window)
}

/// NtUserGetThreadState: the routine `routine` (rtl::user's THREAD_STATE_*): its result.
pub fn thread_state(routine: u32) -> Result<u32, NtStatus> {
    let mut result = 0u32;
    // SAFETY: the kernel writes the result into the local.
    checked(unsafe { raw::NtUserGetThreadState(routine, &mut result) })?;
    Ok(result)
}

/// NtUserCallHwndParamLock: the routine `routine` (rtl::user's HWND_PARAM_LOCK_*) on `window` with
/// `param`: its result.
pub fn call_hwnd_param_lock(window: usize, param: u32, routine: u32) -> Result<u32, NtStatus> {
    let mut result = 0u32;
    // SAFETY: the kernel writes the result into the local.
    checked(unsafe { raw::NtUserCallHwndParamLock(window, param, routine, &mut result) })?;
    Ok(result)
}

// --- win32k: painting ----------------------------------------------------------------------------

/// NtUserInvalidateRect: the rectangle at `rect` (zero: the client area) added to `window`'s update
/// region.
pub fn invalidate_rect(window: usize, rect: usize, erase: bool) -> Result<(), NtStatus> {
    // SAFETY: the kernel reads the rectangle through its fault-tolerant copies.
    checked(unsafe { raw::NtUserInvalidateRect(window, rect, erase as u32) })
}

/// NtUserValidateRect: the rectangle at `rect` (zero: all of it) taken out of `window`'s update
/// region.
pub fn validate_rect(window: usize, rect: usize) -> Result<(), NtStatus> {
    // SAFETY: the kernel reads the rectangle through its fault-tolerant copies.
    checked(unsafe { raw::NtUserValidateRect(window, rect) })
}

/// NtUserGetUpdateRect: `window`'s update region's box into the RECT at `rect` (zero: none), its
/// answer bits (rtl::user's UPDATE_*).
pub fn update_rect(window: usize, rect: usize, erase: bool) -> Result<u32, NtStatus> {
    let mut bits = 0u32;
    // SAFETY: the kernel writes the rectangle through its fault-tolerant copies, and the bits into
    // the local.
    checked(unsafe { raw::NtUserGetUpdateRect(window, rect, erase as u32, &mut bits) })?;
    Ok(bits)
}

/// NtUserBeginPaint: the PAINTSTRUCT at `paint` filled, its DC made, `window` validated.
pub fn begin_paint(window: usize, paint: usize) -> Result<(), NtStatus> {
    // SAFETY: the kernel writes the structure through its fault-tolerant copies.
    checked(unsafe { raw::NtUserBeginPaint(window, paint) })
}

/// NtUserEndPaint: the DC of the PAINTSTRUCT at `paint` released.
pub fn end_paint(window: usize, paint: usize) -> Result<(), NtStatus> {
    // SAFETY: the kernel reads the structure through its fault-tolerant copies.
    checked(unsafe { raw::NtUserEndPaint(window, paint) })
}

// --- win32k: DCs ---------------------------------------------------------------------------------

/// NtUserGetDC: a DC of `window` (zero: the screen).
pub fn get_dc(window: usize) -> Result<u32, NtStatus> {
    let mut dc = 0u32;
    // SAFETY: the kernel writes the handle into the local.
    checked(unsafe { raw::NtUserGetDC(window, &mut dc) })?;
    Ok(dc)
}

/// NtUserGetDCEx: a DC of `window` with GetDCEx's region and flags.
pub fn get_dc_ex(window: usize, region: usize, flags: u32) -> Result<u32, NtStatus> {
    let mut dc = 0u32;
    // SAFETY: the kernel writes the handle into the local.
    checked(unsafe { raw::NtUserGetDCEx(window, region, flags, &mut dc) })?;
    Ok(dc)
}

/// NtUserGetWindowDC: a DC of `window`'s whole rectangle.
pub fn get_window_dc(window: usize) -> Result<u32, NtStatus> {
    let mut dc = 0u32;
    // SAFETY: the kernel writes the handle into the local.
    checked(unsafe { raw::NtUserGetWindowDC(window, &mut dc) })?;
    Ok(dc)
}

// --- win32k: the display -------------------------------------------------------------------------

/// NtUserEnumDisplaySettings: mode `mode` of the display named at `device` (zero: the primary
/// one), described into the DEVMODEW at `dev_mode` in win32k's own version (dmSize 188, whatever
/// the caller's; a dmSize short of that refused).
pub fn enum_display_settings(
    device: usize,
    mode: u32,
    dev_mode: usize,
    flags: u32,
) -> Result<(), NtStatus> {
    // SAFETY: the kernel reads the name and reads and writes the structure through its
    // fault-tolerant copies.
    checked(unsafe { raw::NtUserEnumDisplaySettings(device, mode, dev_mode, flags) })
}

/// NtUserEnumDisplayDevices: device `number` under the one named at `device` (zero: the
/// adapters), into the DISPLAY_DEVICEW at `out` as far as its cb goes.
pub fn enum_display_devices(
    device: usize,
    number: u32,
    out: usize,
    flags: u32,
) -> Result<(), NtStatus> {
    // SAFETY: the kernel reads the name and reads and writes the structure through its
    // fault-tolerant copies.
    checked(unsafe { raw::NtUserEnumDisplayDevices(device, number, out, flags) })
}

/// NtUserEnumDisplayMonitors: the monitors the DC `dc` (zero: none) and the RECT at `clip` (zero:
/// none) meet, their handles and rectangles into the arrays (as many as both hold): how many there
/// are.
pub fn enum_display_monitors(
    dc: usize,
    clip: usize,
    monitors: &mut [u32],
    rects: &mut [Rect],
) -> Result<u32, NtStatus> {
    let count = monitors.len().min(rects.len()) as u32;
    let mut found = 0u32;
    // SAFETY: the kernel reads the clipping rectangle through its fault-tolerant copies, and
    // writes at most `count` entries of the local arrays and the count into the local.
    checked(unsafe {
        raw::NtUserEnumDisplayMonitors(
            dc,
            clip,
            monitors.as_mut_ptr(),
            rects.as_mut_ptr(),
            count,
            &mut found,
        )
    })?;
    Ok(found)
}

/// The MonitorEnumProc `proc` the program handed EnumDisplayMonitors, called with a monitor: its
/// answer (zero stops the enumeration).
pub fn call_monitor_procedure(proc: u32, monitor: u32, dc: usize, rect: &Rect, data: usize) -> u32 {
    // SAFETY: `proc` is the program's own callback, handed to EnumDisplayMonitors for this; the
    // rectangle lives for the call.
    unsafe { raw::call_monitor_procedure(proc, monitor, dc, rect, data) }
}

/// NtUserSetSysColors: `count` system colors set, their indexes and COLORREFs in the arrays at
/// `indexes` and `colors`.
pub fn set_sys_colors(count: u32, indexes: usize, colors: usize) -> Result<(), NtStatus> {
    // SAFETY: the kernel reads the arrays through its fault-tolerant copies.
    checked(unsafe { raw::NtUserSetSysColors(count, indexes, colors, 0) })
}

/// NtUserSystemParametersInfo: SystemParametersInfoW's action, its answer at `param`.
pub fn system_parameters_info(
    action: u32,
    ui_param: u32,
    param: usize,
    win_ini: u32,
) -> Result<(), NtStatus> {
    // SAFETY: the kernel reads and writes the parameter through its fault-tolerant copies.
    checked(unsafe { raw::NtUserSystemParametersInfo(action, ui_param, param, win_ini) })
}

// --- win32k: the menus, the accelerators, the cursors and icons
// -----------------------------------

/// NtUserCallNoParam: the routine `routine` (rtl::user's NO_PARAM_*): its result.
pub fn call_no_param(routine: u32) -> Result<u32, NtStatus> {
    let mut result = 0;
    // SAFETY: the kernel writes the local.
    checked(unsafe { raw::NtUserCallNoParam(routine, &mut result) })?;
    Ok(result)
}

/// NtUserThunkedMenuItemInfo's insertion or change (rtl::menu's MENU_ITEM_INSERT, MENU_ITEM_SET):
/// the item `info` describes, before or on the item `item` names in `menu` (MF_BYPOSITION in
/// `flags`), its text `text` (`info`'s cch its length).
pub fn set_menu_item(
    menu: usize,
    item: u32,
    flags: u32,
    operation: u32,
    info: &MenuItemInfoW,
    text: &[u16],
) -> Result<(), NtStatus> {
    let mut copy = *info;
    copy.cch = text.len() as u32;
    let at = if text.is_empty() {
        core::ptr::null()
    } else {
        text.as_ptr()
    };
    // SAFETY: the kernel reads the local structure and the text, as many units as its cch says,
    // through its fault-tolerant copies.
    checked(unsafe {
        raw::NtUserThunkedMenuItemInfo(
            menu,
            item,
            flags,
            operation,
            copy.as_bytes_mut().as_mut_ptr(),
            at,
        )
    })
}

/// NtUserThunkedMenuItemInfo's queries (rtl::menu's MENU_ITEM_QUERY, MENU_QUERY): the item `item`
/// names in `menu`, or the menu, into `answer`.
pub fn query_menu(
    menu: usize,
    item: u32,
    flags: u32,
    operation: u32,
    answer: &mut MenuItemAnswer,
) -> Result<(), NtStatus> {
    // SAFETY: the kernel writes the local answer.
    checked(unsafe {
        raw::NtUserThunkedMenuItemInfo(
            menu,
            item,
            flags,
            operation,
            answer.as_bytes_mut().as_mut_ptr(),
            core::ptr::null(),
        )
    })
}

/// NtUserDestroyMenu: `menu` and its popups destroyed.
pub fn destroy_menu(menu: usize) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtUserDestroyMenu(menu) })
}

/// NtUserCheckMenuItem: CheckMenuItem's change; the item's previous check.
pub fn check_menu_item(menu: usize, item: u32, check: u32) -> Result<u32, NtStatus> {
    let mut previous = 0;
    // SAFETY: the kernel writes the local.
    checked(unsafe { raw::NtUserCheckMenuItem(menu, item, check, &mut previous) })?;
    Ok(previous)
}

/// NtUserEnableMenuItem: EnableMenuItem's change; the item's previous enabling bits.
pub fn enable_menu_item(menu: usize, item: u32, enable: u32) -> Result<u32, NtStatus> {
    let mut previous = 0;
    // SAFETY: the kernel writes the local.
    checked(unsafe { raw::NtUserEnableMenuItem(menu, item, enable, &mut previous) })?;
    Ok(previous)
}

/// NtUserSetMenu: the window's menu set (0: none).
pub fn set_menu(window: usize, menu: usize) -> Result<(), NtStatus> {
    // SAFETY: no pointers.
    checked(unsafe { raw::NtUserSetMenu(window, menu, 1) })
}

/// NtUserCreateAcceleratorTable: a table of `entries`, or with `resource` (its data's address in
/// the module `module`) the one loaded from it before; its handle.
pub fn create_accelerator_table(
    entries: &[Accel],
    module: usize,
    resource: usize,
) -> Result<usize, NtStatus> {
    let mut table = 0;
    // SAFETY: the kernel reads the entries, as many as the count says, and writes the local.
    checked(unsafe {
        raw::NtUserCreateAcceleratorTable(
            entries.as_ptr(),
            entries.len() as u32,
            module,
            resource,
            &mut table,
        )
    })?;
    Ok(table as usize)
}

/// NtUserCopyAcceleratorTable: with no buffer the table's entry count; else as many of its entries
/// as `entries` holds into it, their number.
pub fn copy_accelerator_table(
    table: usize,
    entries: Option<&mut [Accel]>,
) -> Result<u32, NtStatus> {
    let (at, count) = match entries {
        Some(entries) => (entries.as_mut_ptr(), entries.len() as u32),
        None => (core::ptr::null_mut(), 0),
    };
    let mut copied = 0;
    // SAFETY: the kernel writes at most `count` entries of the buffer, and the local.
    checked(unsafe { raw::NtUserCopyAcceleratorTable(table, at, count, &mut copied) })?;
    Ok(copied)
}

/// NtUserDestroyAcceleratorTable: the table's load count down; whether it was destroyed.
pub fn destroy_accelerator_table(table: usize) -> Result<bool, NtStatus> {
    let mut destroyed = 0;
    // SAFETY: the kernel writes the local.
    checked(unsafe { raw::NtUserDestroyAcceleratorTable(table, &mut destroyed) })?;
    Ok(destroyed != 0)
}

/// NtUserTranslateAccelerator: `msg` translated for `window` through `table`; whether it was an
/// accelerator (the messages it sent queued for the window's thread).
pub fn translate_accelerator(window: usize, table: usize, msg: &Msg) -> Result<bool, NtStatus> {
    let mut translated = 0;
    // SAFETY: the kernel reads the local MSG and writes the local answer.
    checked(unsafe { raw::NtUserTranslateAccelerator(window, table, msg, &mut translated) })?;
    Ok(translated != 0)
}

/// NtUserFindExistingCursorIcon: the shared icon or cursor (`kind` RT_ICON or RT_CURSOR) loaded
/// from the module's resource at `width` by `height`, or with the module 0 the stock one of the
/// IDC_ or IDI_ id `resource`; 0 for none.
pub fn find_existing_cursor_icon(
    module: usize,
    resource: usize,
    width: i32,
    height: i32,
    kind: u16,
) -> Result<usize, NtStatus> {
    let mut cursor = 0;
    let size = (width as u16 as u32) | ((height as u16 as u32) << 16);
    // SAFETY: the kernel writes the local.
    checked(unsafe {
        raw::NtUserFindExistingCursorIcon(module, resource, size, u32::from(kind), &mut cursor)
    })?;
    Ok(cursor as usize)
}

/// NtUserSetCursorIconData: the empty record `cursor` filled in from `data`.
pub fn set_cursor_icon_data(cursor: usize, data: &CursorData) -> Result<(), NtStatus> {
    // SAFETY: the kernel reads the local structure.
    checked(unsafe { raw::NtUserSetCursorIconData(cursor, data) })
}

/// NtUserGetIconInfo: what the cursor or icon `cursor` holds.
pub fn get_icon_info(cursor: usize) -> Result<CursorData, NtStatus> {
    let mut data = CursorData::default();
    // SAFETY: the kernel writes the local structure.
    checked(unsafe { raw::NtUserGetIconInfo(cursor, &mut data) })?;
    Ok(data)
}

/// NtUserDestroyCursor: the cursor or icon `cursor` destroyed (a shared one stays).
pub fn destroy_cursor(cursor: usize) -> Result<(), NtStatus> {
    // SAFETY: a handle, no memory.
    checked(unsafe { raw::NtUserDestroyCursor(cursor) })
}

/// The host tests' imports: stand-ins with the imports' shapes, recording what they were given,
/// and a window manager of their own behind the services ([`host::Wm`]).
#[cfg(test)]
#[allow(non_snake_case)]
pub mod host;
